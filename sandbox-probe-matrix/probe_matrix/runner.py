"""Run one accurately labelled harness/mode cell.

Adapter extension point: replace UnavailableAdapter with an implementation that
executes a serialized probe ID under a real, verified sandbox profile and returns
the child result. Wire a sandbox-exec profile here only with tests proving the
requested policy was applied. CLI presence, inherited harness environment, or
running an agent with a prompt is NOT evidence of sandbox enforcement.

The shell adapter runs directly in this process and measures its inherited
permissions. It never claims to have installed or escaped a sandbox.
"""

from __future__ import annotations

import dataclasses
import os
import signal
import tempfile
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from probes.core._base import os_failure

from probe_matrix.safety import assert_safe_environment
from probe_matrix.spec import Probe, ProbeContext, ProbeResult, Verdict

_MODES = {
    "shell": ("default",),
    "claude-code": ("default", "sandboxed"),
    "codex": ("read-only", "workspace-write", "danger-full-access"),
}
_PROBE_BUDGET = 3.0  # allows a bounded 2s child/socket to close itself first


def available_harnesses() -> list[str]:
    """Known adapter names, including explicitly unavailable adapters."""
    return list(_MODES)


def modes_for(harness: str) -> list[str]:
    if harness not in _MODES:
        raise ValueError("unknown harness; use an advertised adapter name")
    return list(_MODES[harness])


class Adapter(Protocol):
    def run(self, probe: Probe, ctx: ProbeContext) -> ProbeResult: ...


class UnavailableAdapter:
    """No agent CLI is invoked until a real policy-enforcing adapter is wired."""

    def run(self, probe: Probe, ctx: ProbeContext) -> ProbeResult:
        return ProbeResult(
            probe.id,
            probe.category,
            Verdict.SKIPPED,
            "adapter unavailable: no verified sandbox invocation configured for this mode",
            ctx.harness,
            ctx.mode,
        )


def _expired(_signum: int, _frame: object) -> None:
    raise TimeoutError("probe budget exceeded")


class ShellAdapter:
    def run(self, probe: Probe, ctx: ProbeContext) -> ProbeResult:
        # Do not replace another owner's timer, or run unbounded in a worker
        # thread (Python only delivers SIGALRM to the main thread).
        if threading.current_thread() is not threading.main_thread() or not hasattr(
            signal, "setitimer"
        ):
            return ProbeResult(
                probe.id,
                probe.category,
                Verdict.SKIPPED,
                "safe probe timebox unavailable in this execution context",
            )
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            return ProbeResult(
                probe.id,
                probe.category,
                Verdict.SKIPPED,
                "safe probe timebox unavailable while an existing timer is active",
            )
        handler = signal.getsignal(signal.SIGALRM)
        try:
            signal.signal(signal.SIGALRM, _expired)
            signal.setitimer(signal.ITIMER_REAL, _PROBE_BUDGET)
            return probe.run(ctx)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, handler)


def _run(probes: list[Probe], ctx: ProbeContext, adapter: Adapter) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for probe in probes:
        start = time.monotonic()
        try:
            if ctx.dry_run:
                result = ProbeResult(
                    probe.id, probe.category, Verdict.SKIPPED, "dry-run: action not performed"
                )
            else:
                result = adapter.run(probe, ctx)
        except OSError as exc:
            verdict, detail = os_failure(exc)
            result = ProbeResult(probe.id, probe.category, verdict, detail)
        except Exception:
            result = ProbeResult(
                probe.id,
                probe.category,
                Verdict.ERROR,
                "probe failed; diagnostic values suppressed",
            )
        results.append(
            dataclasses.replace(
                result,
                harness=ctx.harness,
                mode=ctx.mode,
                elapsed_ms=max(0, int((time.monotonic() - start) * 1000)),
            )
        )
    return results


def run_cell(harness: str, mode: str, probes: Iterable[Probe], dry_run: bool,
             extra: dict[str, str] | None = None) -> list[ProbeResult]:
    """Run each probe once; expected denials and individual errors are results.

    Runner-owned fixtures exist only during a real shell cell, under the current
    workdir. The probes themselves never write. Dry-run creates no fixtures.
    Preflight is repeated here so library callers cannot bypass the CLI guard.
    """
    assert_safe_environment(args=[])
    if mode not in modes_for(harness):
        raise ValueError("unknown mode for selected harness")
    selected = list(probes)
    ctx = ProbeContext(harness=harness, mode=mode, dry_run=dry_run)
    if extra:
        ctx.extra.update(extra)
    if dry_run or harness != "shell":
        return _run(selected, ctx, UnavailableAdapter())
    try:
        fixture = tempfile.TemporaryDirectory(prefix=".spm-", dir=os.getcwd())
    except OSError:
        # A read-only working directory must not prevent read/socket/exec probes.
        # No symlink is followed when the runner could not create its fixture.
        ctx.workdir = os.getcwd()
        return _run(selected, ctx, ShellAdapter())
    with fixture as scratch:
        ctx.workdir = scratch
        try:
            (Path(scratch) / "boundary-link").symlink_to("/etc/hosts")
            ctx.extra["symlink_fixture"] = "ready"
        except OSError:
            # Fixture creation is not the probe: do not mislabel it as a deny.
            pass
        return _run(selected, ctx, ShellAdapter())
