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
    if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
        return Verdict.BLOCKED, "operation denied (permission)"
    if exc.errno == errno.ECONNREFUSED:
        # Refusal means no listener OR a sandbox block; without an independent
        # control we cannot tell, so this is inconclusive, not a demonstrated deny.
        return Verdict.SKIPPED, "connection refused (no listener or blocked; inconclusive)"
    if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EAFNOSUPPORT}:
        return Verdict.SKIPPED, "network or address family unavailable (offline self-check)"
    if isinstance(exc, TimeoutError):
        # A timeout (slow child/service/socket) does not demonstrate a sandbox
        # denial; it is inconclusive, consistent with ECONNREFUSED and keychain.
        return Verdict.SKIPPED, "operation timed out; inconclusive (not a denial)"
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
                # A slow child does not demonstrate a denial; inconclusive, like a
                # socket/keychain timeout, so a later success is not a false regression.
                verdict, detail = Verdict.SKIPPED, "child process timed out; inconclusive (not a denial)"
            except Exception:
                verdict, detail = Verdict.ERROR, "probe failed; diagnostic values suppressed"
        return ProbeResult(self.id, self.category, verdict, detail, ctx.harness, ctx.mode)
