import json
import subprocess
from typing import Any

import pytest

from probe_matrix.spec import ProbeContext, Verdict, all_probes
import probes.keychain as keychain_wing


@pytest.mark.parametrize("dry_run,enabled", [(False, None), (True, None), (True, "1"), (False, "yes")])
def test_default_and_dry_run_never_access_keychain(
    dry_run: bool, enabled: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("opt-out must not start any process")

    monkeypatch.setattr(keychain_wing.subprocess, "run", forbidden)
    extra = {} if enabled is None else {"keychain_enabled": enabled}
    result = keychain_wing.KeychainReachProbe().run(ProbeContext(dry_run=dry_run, extra=extra))
    assert result.verdict == Verdict.SKIPPED
    assert result.detail == "keychain wing: dry-run/opt-in"


def test_opt_in_metadata_counts_never_emit_planted_secrets(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str],
) -> None:
    # Only fake subprocess output is used; no real keychain or item is accessed.
    secrets = ["PLANTED_PASSWORD_932feb", "PLANTED_ACCOUNT_8d136a", "PLANTED_STDERR_168bbe"]
    metadata = (
        'class: "genp"\n    "acct"<blob>="' + secrets[1] + '"\n'
        'data:\n"' + secrets[0] + '"\n'
        'class: "inet"\nclass: 0x67656e70\nclass: "cert"\n'
    )
    monkeypatch.setattr(keychain_wing.sys, "platform", "darwin")

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args == ["/usr/bin/security", "dump-keychain"]
        assert "-d" not in args and "-w" not in args and "-g" not in args
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(args, 0, stdout=metadata, stderr=secrets[2])

    monkeypatch.setattr(keychain_wing.subprocess, "run", fake_run)
    probe = keychain_wing.KeychainReachProbe()
    assert any(item.id == probe.id for item in all_probes())
    result = probe.run(ProbeContext(extra={"keychain_enabled": "1"}, harness="test", mode="fixture"))
    assert result.verdict == Verdict.ALLOWED
    assert "generic_password=2" in result.detail
    assert "internet_password=1" in result.detail
    assert "total=3" in result.detail
    assert "unprompted secret readability: unknown" in result.detail
    assert result.harness == "test" and result.mode == "fixture"
    print(json.dumps(result.to_json()))
    captured = capfd.readouterr()
    for sentinel in secrets:
        assert sentinel not in captured.out + captured.err + repr(result)


@pytest.mark.parametrize("failure", ["denied", "oserror", "timeout"])
def test_failures_do_not_echo_metadata_or_diagnostics(
    failure: str, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str],
) -> None:
    sentinel = "PLANTED_FAILURE_SECRET_17bacf"
    monkeypatch.setattr(keychain_wing.sys, "platform", "darwin")

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if failure == "oserror":
            raise PermissionError(sentinel)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 10, output=sentinel, stderr=sentinel)
        return subprocess.CompletedProcess(args, 1, stdout=sentinel, stderr=sentinel)

    monkeypatch.setattr(keychain_wing.subprocess, "run", fake_run)
    result = keychain_wing.KeychainReachProbe().run(ProbeContext(extra={"keychain_enabled": "1"}))
    # A timeout is inconclusive (ERROR); a denial/nonzero exit is BLOCKED. Either
    # way, no planted metadata/diagnostic value may appear in the output.
    expected = Verdict.ERROR if failure == "timeout" else Verdict.BLOCKED
    assert result.verdict == expected
    print(json.dumps(result.to_json()))
    captured = capfd.readouterr()
    assert sentinel not in captured.out + captured.err + repr(result)


def test_non_macos_skips_without_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keychain_wing.sys, "platform", "linux")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("non-macOS must not start a process")

    monkeypatch.setattr(keychain_wing.subprocess, "run", forbidden)
    result = keychain_wing.KeychainReachProbe().run(ProbeContext(extra={"keychain_enabled": "1"}))
    assert result.verdict == Verdict.SKIPPED


def test_keychain_timeout_through_shell_adapter_is_error(monkeypatch):
    """A slow enumeration surfaced as ERROR (not a false BLOCKED) via the runner."""
    from probe_matrix.runner import run_cell
    from probe_matrix.spec import get_probe
    import probes.keychain as kc

    monkeypatch.setattr(kc.sys, "platform", "darwin")

    def slow(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 2.5))

    monkeypatch.setattr(kc.subprocess, "run", slow)
    probe = get_probe("keychain.metadata-reach")
    assert probe is not None
    results = run_cell("shell", "default", [probe], False, extra={"keychain_enabled": "1"})
    assert results[0].verdict == Verdict.ERROR
    assert "inconclusive" in results[0].detail
