"""Shared bounded operations; exception text and resource values never leave probes."""

from __future__ import annotations

import errno
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict

TIMEOUT = 2.0
Outcome = tuple[Verdict, str]


def os_failure(exc: OSError) -> Outcome:
    if isinstance(exc, FileNotFoundError):
        return Verdict.SKIPPED, "resource absent"
    if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS, errno.ECONNREFUSED}:
        return Verdict.BLOCKED, "operation denied or connection refused"
    if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EAFNOSUPPORT}:
        return Verdict.SKIPPED, "network or address family unavailable (offline self-check)"
    if isinstance(exc, TimeoutError):
        return Verdict.BLOCKED, "operation timed out within probe budget"
    return Verdict.ERROR, "operation failed without a conclusive boundary result"


@dataclass
class CoreProbe:
    """Each registered instance is one question with a bounded safe action.

    Local metadata syscalls rely on the local filesystem; no remote mounts or
    user-supplied paths are enumerated. Sockets and child processes have 2s caps.
    """

    id: str
    category: Category
    title: str
    description: str
    safety_note: str
    action: Callable[[ProbeContext], Outcome]

    def run(self, ctx: ProbeContext) -> ProbeResult:
        if ctx.dry_run:
            verdict, detail = Verdict.SKIPPED, "dry-run: action not performed"
        else:
            try:
                verdict, detail = self.action(ctx)
            except OSError as exc:
                verdict, detail = os_failure(exc)
            except subprocess.TimeoutExpired:
                verdict, detail = Verdict.BLOCKED, "child process exceeded probe budget"
            except Exception:
                verdict, detail = Verdict.ERROR, "probe failed; diagnostic values suppressed"
        return ProbeResult(self.id, self.category, verdict, detail, ctx.harness, ctx.mode)
