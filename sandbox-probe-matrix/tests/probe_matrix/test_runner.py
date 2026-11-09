from __future__ import annotations

import errno
import signal
import time
from pathlib import Path

import pytest
from probe_matrix import runner
from probe_matrix.probes import core as _core  # noqa: F401
from probe_matrix.runner import available_harnesses, modes_for, run_cell
from probe_matrix.safety import UnsafeEnvironment
from probe_matrix.spec import Category, ProbeContext, Verdict, all_probes
from probes.core._base import CoreProbe, Outcome


def _never(_: ProbeContext) -> Outcome:
    raise AssertionError("action must not run")


def _probe(action=_never) -> CoreProbe:
    return CoreProbe("test.boundary", Category.FILES, "Test", "Test?", "No data", action)


def test_registry_and_dry_run_do_not_create_fixtures(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("dry-run must not create scratch files")

    monkeypatch.setattr(runner.tempfile, "TemporaryDirectory", forbidden)
    probes = all_probes()
    assert len(probes) >= 30
    assert len({probe.id for probe in probes}) == len(probes)
    assert {probe.category for probe in probes} >= {
        Category.FILES,
        Category.SOCKETS,
        Category.NETWORK,
        Category.APP_LAUNCH,
    }
    assert all(probe.safety_note for probe in probes)
    results = run_cell("shell", "default", [_probe()], True)
    assert len(results) == 1 and results[0].verdict == Verdict.SKIPPED


def test_real_run_closes_and_removes_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    seen: list[Path] = []

    def action(ctx: ProbeContext) -> Outcome:
        scratch = Path(ctx.workdir)
        assert scratch.parent == tmp_path
        assert (scratch / "boundary-link").is_symlink()
        seen.append(scratch)
        return Verdict.ALLOWED, "fixture reachable"

    results = run_cell("shell", "default", [_probe(action)], False)
    assert results[0].verdict == Verdict.ALLOWED
    assert seen and all(not path.exists() for path in seen)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "error, verdict",
    [
        (PermissionError(errno.EACCES, "private-value"), Verdict.BLOCKED),
        (ConnectionRefusedError(errno.ECONNREFUSED, "private-value"), Verdict.BLOCKED),
        (FileNotFoundError(errno.ENOENT, "private-value"), Verdict.SKIPPED),
        (RuntimeError("private-value"), Verdict.ERROR),
    ],
)
def test_failures_are_results(
    error: Exception, verdict: Verdict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    def action(_: ProbeContext) -> Outcome:
        raise error

    results = run_cell(
        "shell", "default", [_probe(action), _probe(lambda c: (Verdict.ALLOWED, "ok"))], False
    )
    assert [result.verdict for result in results] == [verdict, Verdict.ALLOWED]
    assert "private-value" not in str([result.to_json() for result in results])
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_time_budget_restores_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "_PROBE_BUDGET", 0.01)
    previous = signal.getsignal(signal.SIGALRM)

    def action(_: ProbeContext) -> Outcome:
        time.sleep(1)
        return Verdict.ALLOWED, "unexpected"

    result = run_cell("shell", "default", [_probe(action)], False)[0]
    assert result.verdict == Verdict.BLOCKED
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert not list(tmp_path.iterdir())


def test_non_shell_adapters_do_not_execute() -> None:
    assert available_harnesses() == ["shell", "claude-code", "codex"]
    for harness in ("claude-code", "codex"):
        for mode in modes_for(harness):
            result = run_cell(harness, mode, [_probe()], False)[0]
            assert result.verdict == Verdict.SKIPPED
            assert result.detail.startswith("adapter unavailable:")
            assert (result.harness, result.mode) == (harness, mode)


def test_denied_scratch_does_not_abort_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    def denied(*args: object, **kwargs: object) -> None:
        raise PermissionError(errno.EACCES, "private-value")

    monkeypatch.setattr(runner.tempfile, "TemporaryDirectory", denied)
    selected = [
        probe for probe in all_probes() if probe.id in {"files.workdir-read", "files.symlink-out"}
    ]
    results = run_cell("shell", "default", selected, False)
    assert {result.probe_id: result.verdict for result in results} == {
        "files.workdir-read": Verdict.ALLOWED,
        "files.symlink-out": Verdict.SKIPPED,
    }
    assert not list(tmp_path.iterdir())


def test_preflight_guards_library_and_invalid_cells(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPM_TARGET_HOST", "remote.invalid")
    with pytest.raises(UnsafeEnvironment):
        run_cell("shell", "default", [_probe()], True)
    monkeypatch.delenv("SPM_TARGET_HOST")
    with pytest.raises(ValueError):
        run_cell("unknown", "default", [], True)
    with pytest.raises(ValueError):
        run_cell("shell", "workspace-write", [], True)
