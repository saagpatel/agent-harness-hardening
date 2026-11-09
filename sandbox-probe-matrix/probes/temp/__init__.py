"""Shared Temp Leak wing — a READ-ONLY cross-session reachability check.

A true cross-session temp leak can only be measured across two independent
sessions: one *writer* session seeds a marker in its own temp area, and a
separate *reader* session (this probe) attempts to read it WITHOUT writing
anything. The runner cannot fabricate a second session in-process, so unless a
real writer handoff is supplied this wing reports SKIPPED (unsupported here) —
never a false ALLOWED from reading a marker the same process just wrote.

Supply the handoff via `ctx.extra`:
  * `writer_marker`   — absolute path to the marker an independent writer session
                        created (this probe NEVER creates it);
  * `writer_sentinel` — hex of the marker's expected contents;
  * `reader_root`     — this reader session's temp root, from which the marker
                        path is resolved.
The probe attempts a read-only read from the reader root: ALLOWED if it reaches
the writer's sentinel, BLOCKED if it cannot. It writes nothing and deletes
nothing (the writer session owns the marker's lifecycle).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict, register


# Only a permission/read-only denial demonstrates that the boundary held.
_DENIED_ERRNOS = {errno.EACCES, errno.EPERM, errno.EROFS}


def _read_only_reach(reader_root: Path, writer_marker: Path, sentinel: bytes) -> tuple[Verdict, str]:
    """Attempt, read-only, to reach the writer's marker from the reader's root.

    * read + sentinel match        -> ALLOWED (cross-session leak demonstrated)
    * read denied (EACCES/EPERM)   -> BLOCKED (isolation demonstrated)
    * marker missing / I/O error   -> ERROR  (inconclusive: invalid handoff/env)
    * read ok but sentinel mismatch-> ERROR  (inconclusive: unverified handoff)
    """
    relative = os.path.relpath(writer_marker, reader_root)
    try:
        data = (reader_root / relative).read_bytes()
    except OSError as exc:
        if exc.errno in _DENIED_ERRNOS:
            return Verdict.BLOCKED, "reader denied access to the writer's marker"
        return Verdict.ERROR, "marker unreachable (missing/io); inconclusive handoff"
    if data == sentinel:
        return Verdict.ALLOWED, "reader read the writer's marker"
    return Verdict.ERROR, "sentinel mismatch; handoff unverified (inconclusive)"


class SharedTempLeakProbe:
    id = "temp.shared-session-leak"
    category = Category.TEMP
    title = "Shared Temp Leak"
    description = "Can this reader session read a marker another session left in temp?"
    safety_note = (
        "Read-only: the probe reads an independently-created marker and writes/"
        "deletes nothing. Without a real writer-session handoff it reports SKIPPED "
        "rather than fabricating a same-process result."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        def result(verdict: Verdict, detail: str) -> ProbeResult:
            return ProbeResult(
                self.id, self.category, verdict, detail,
                harness=ctx.harness, mode=ctx.mode,
            )

        if ctx.dry_run:
            return result(Verdict.SKIPPED, "temp wing: dry-run")

        marker = ctx.extra.get("writer_marker")
        sentinel_hex = ctx.extra.get("writer_sentinel")
        reader_root = ctx.extra.get("reader_root")
        if not (marker and sentinel_hex and reader_root):
            return result(
                Verdict.SKIPPED,
                "temp wing: cross-session leak unsupported in-process; supply an "
                "independent writer session's marker (writer_marker + writer_sentinel) "
                "and this reader session's root (reader_root)",
            )
        try:
            sentinel = bytes.fromhex(sentinel_hex)
        except ValueError:
            return result(Verdict.ERROR, "temp wing: writer_sentinel is not valid hex")
        try:
            verdict, why = _read_only_reach(
                Path(reader_root).absolute(), Path(marker).absolute(), sentinel
            )
        except OSError:
            return result(Verdict.ERROR, "temp wing: read-only reach failed to resolve")
        return result(
            verdict,
            f"read-only cross-session reach: {why} "
            "(independent writer marker; nothing written or deleted)",
        )


register(SharedTempLeakProbe())
