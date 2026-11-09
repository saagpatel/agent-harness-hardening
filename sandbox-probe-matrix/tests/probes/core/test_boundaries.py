from __future__ import annotations

import errno
import socket
import subprocess
from pathlib import Path

import pytest
from probe_matrix.probes import core as _core  # noqa: F401
from probe_matrix.spec import ProbeContext, Verdict, all_probes, get_probe
from probes.core import app_launch, files, network


def test_every_direct_probe_honors_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("no syscalls during dry-run")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    for probe in all_probes():
        result = probe.run(ProbeContext(dry_run=True))
        assert result.verdict == Verdict.SKIPPED
        assert "dry-run" in result.detail


@pytest.mark.parametrize(
    "number, verdict",
    [
        (errno.EACCES, Verdict.BLOCKED),
        (errno.ECONNREFUSED, Verdict.SKIPPED),
        (errno.ENETUNREACH, Verdict.SKIPPED),
        (errno.EHOSTUNREACH, Verdict.SKIPPED),
    ],
)
def test_offline_network_and_denials_are_results(
    number: int, verdict: Verdict, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*args: object) -> None:
        raise OSError(number, "suppressed-diagnostic")

    monkeypatch.setattr(socket, "socket", unavailable)
    probe = get_probe("network.tcp-ipv4")
    assert probe is not None
    assert probe.run(ProbeContext()).verdict == verdict


def test_network_timeout_and_dns_selfcheck(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("dns", 2)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert network._dns(ProbeContext())[0] == Verdict.SKIPPED


@pytest.mark.parametrize(
    "returncode, verdict",
    [
        (0, Verdict.ALLOWED),
        (2, Verdict.SKIPPED),
        (3, Verdict.BLOCKED),
    ],
)
def test_dns_child_is_bounded_and_discards_output(
    returncode: int, verdict: Verdict, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, object]] = []

    def child(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert args[1:3] == ["-I", "-c"]
        seen.append(kwargs)
        return subprocess.CompletedProcess(args, returncode)

    monkeypatch.setattr(subprocess, "run", child)
    assert network._dns(ProbeContext())[0] == verdict
    assert seen[0]["timeout"] == 2
    assert seen[0]["stdout"] == subprocess.DEVNULL
    assert seen[0]["stderr"] == subprocess.DEVNULL


def test_tcp_connect_never_sends_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[object] = []

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *args: object) -> None:
            events.append("close")

        def settimeout(self, timeout: float) -> None:
            events.append(timeout)

        def connect(self, address: tuple[str, int]) -> None:
            events.append(address)

    monkeypatch.setattr(socket, "socket", lambda *args: Client())
    assert network._tcp(socket.AF_INET, "1.1.1.1")[0] == Verdict.ALLOWED
    assert events == [2.0, ("1.1.1.1", 443), "close"]


def test_write_checks_are_only_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(files.os, "access", lambda *args: True)
    verdict, detail = files._write_hint(tmp_path)
    assert verdict == Verdict.SKIPPED
    assert "advisory" in detail and "untested" in detail
    assert not list(tmp_path.iterdir())


def test_app_nonzero_is_not_claimed_as_sandbox_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1)
    )
    assert app_launch._exec(["/usr/bin/true"])[0] == Verdict.ERROR


def test_proxy_values_never_appear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "https://private-value.invalid")
    verdict, detail = network._env(("HTTPS_PROXY",))
    assert verdict == Verdict.ALLOWED
    assert "private-value" not in detail


def test_ssh_only_stats_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(
        files, "_metadata", lambda path: (seen.append(path.name) or Verdict.ALLOWED, "metadata")
    )
    probe = get_probe("files.ssh-presence")
    assert probe is not None
    assert probe.run(ProbeContext()).verdict == Verdict.ALLOWED
    assert seen == [".ssh"]


def test_subprocess_timeout_is_skipped_not_blocked():
    """A child-process timeout is inconclusive (SKIPPED), so a later success is
    not a false blocked->allowed regression."""
    import subprocess
    from probe_matrix.spec import Category, ProbeContext, Verdict
    from probes.core._base import CoreProbe

    def times_out(_ctx):
        raise subprocess.TimeoutExpired(cmd=["/usr/bin/true"], timeout=2)

    probe = CoreProbe("app.slow", Category.APP_LAUNCH, "Slow", "Slow?", "safe", times_out)
    result = probe.run(ProbeContext())
    assert result.verdict == Verdict.SKIPPED
    assert "inconclusive" in result.detail
