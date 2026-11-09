"""Sentinel-only reachability between temp roots, under the current identity.

Two roots model session namespaces, not separate sandbox processes or identities.
Optional supplied roots let the runner select real namespaces without reading any
pre-existing files. Only files exclusively created by this probe are read/deleted.
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import tempfile

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict, register


class _CleanupFailed(Exception):
    pass


class _SetupFailed(Exception):
    """Creating/writing the writer marker failed: nothing was measured."""


def _read_marker(reader_root: Path, marker: Path) -> bytes:
    # Resolve the writer's marker starting from the reader's namespace. No chdir
    # changes the runner's process state, and no existing temp files are scanned.
    relative = os.path.relpath(marker, reader_root)
    return (reader_root / relative).read_bytes()


def _check_roots(writer_root: Path, reader_root: Path) -> Verdict:
    marker: Path | None = None
    try:
        # --- setup: creating/writing the marker is NOT the measured boundary ---
        try:
            sentinel = secrets.token_bytes(32)
            fd, name = tempfile.mkstemp(prefix="spm-marker-", dir=writer_root)
            marker = Path(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(sentinel)
        except OSError as exc:
            raise _SetupFailed from exc
        # --- measurement: can the reader root reach the writer's marker? ---
        # A read failure means the reader cannot reach it: the boundary held.
        try:
            reached = _read_marker(reader_root, marker) == sentinel
        except OSError:
            return Verdict.BLOCKED
        return Verdict.ALLOWED if reached else Verdict.BLOCKED
    finally:
        if marker is not None:
            try:
                marker.unlink()
                # lstat verifies removal even if a dangling symlink were present.
                try:
                    marker.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise _CleanupFailed
            except OSError:
                raise _CleanupFailed from None


class SharedTempLeakProbe:
    id = "temp.shared-session-leak"
    category = Category.TEMP
    title = "Shared Temp Leak"
    description = "Can a reader temp root reach a writer root's random marker?"
    safety_note = (
        "Reads only an exclusively created random sentinel; removes and verifies "
        "every marker. Model directories are confined to the runner's workdir."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        def result(verdict: Verdict, detail: str) -> ProbeResult:
            return ProbeResult(
                self.id, self.category, verdict, detail,
                harness=ctx.harness, mode=ctx.mode,
            )

        if ctx.dry_run:
            return result(Verdict.SKIPPED, "temp wing: dry-run")
        if not ctx.workdir:
            return result(Verdict.ERROR, "temp wing: workdir required")
        supplied_a = ctx.extra.get("session_a_tmp")
        supplied_b = ctx.extra.get("session_b_tmp")
        if bool(supplied_a) != bool(supplied_b):
            return result(Verdict.ERROR, "temp wing: both session roots required")

        scratch: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="spm-temp-", dir=ctx.workdir) as name:
                scratch = name
                root = Path(name)
                writer, reader = root / "session-a", root / "session-b"
                writer.mkdir()
                reader.mkdir()
                # The modeled sibling-directory read runs in ONE process and
                # namespace, so it always succeeds and is only a self-check that the
                # probe mechanism works — NOT a cross-session boundary measurement.
                modeled = _check_roots(writer, reader)
                if supplied_a and supplied_b:
                    # Real measurement: an independent writer session seeded
                    # session_a_tmp and this reader session attempts to reach it.
                    verdict = _check_roots(
                        Path(supplied_a).absolute(), Path(supplied_b).absolute()
                    )
                    detail = (
                        f"supplied session roots: {verdict.value}; "
                        f"modeled self-check: {modeled.value}"
                    )
                else:
                    # No independent session roots: the cross-session boundary was
                    # not exercised, so the cell is inconclusive, not a leak.
                    verdict = Verdict.SKIPPED
                    detail = (
                        "cross-session measurement requires two independent session "
                        "temp roots (ctx.extra session_a_tmp/session_b_tmp); "
                        f"modeled self-check only: {modeled.value}"
                    )
            if Path(scratch).exists():
                raise _CleanupFailed
            return result(verdict, detail + "; cleanup verified")
        except _SetupFailed:
            # Model/supplied root could not be prepared: nothing was measured.
            return result(Verdict.ERROR, "temp wing: marker setup failed; not measured")
        except _CleanupFailed:
            return result(Verdict.ERROR, "temp wing: marker cleanup failed")
        except OSError:
            # Fixture creation (TemporaryDirectory/mkdir) is setup, not a denied read.
            return result(Verdict.ERROR, "temp wing: fixture setup error; not measured")


register(SharedTempLeakProbe())
