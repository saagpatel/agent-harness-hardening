"""Read-only local file boundaries. Never open credential files or enumerate homes."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from probe_matrix.spec import Category, ProbeContext, Verdict, register
from probes.core._base import CoreProbe, Outcome


def _directory(path: Path) -> Outcome:
    # Observe one directory entry, discard its name immediately.
    with os.scandir(path) as entries:
        next(entries, None)
    return Verdict.ALLOWED, "directory read succeeded; names discarded"


def _metadata(path: Path) -> Outcome:
    path.stat()
    return Verdict.ALLOWED, "metadata reachable; no contents read"


def _hosts(_: ProbeContext) -> Outcome:
    with Path("/etc/hosts").open("rb") as handle:
        handle.read(1)
    return Verdict.ALLOWED, "system file read succeeded; data discarded"


def _write_hint(path: Path) -> Outcome:
    path.stat()  # distinguish absence from denied access
    allowed = os.access(path, os.W_OK)
    return (
        Verdict.SKIPPED,
        "advisory write permission "
        + ("present" if allowed else "absent")
        + "; actual write untested to preserve read-only safety",
    )


def _ssh_mode(_: ProbeContext) -> Outcome:
    info = Path(os.path.expanduser("~/.ssh")).stat()
    if not stat.S_ISDIR(info.st_mode):
        return Verdict.SKIPPED, "credential directory absent"
    return Verdict.ALLOWED, "credential directory mode reachable; entries and contents unread"


def _symlink(ctx: ProbeContext) -> Outcome:
    if ctx.extra.get("symlink_fixture") != "ready":
        return Verdict.SKIPPED, "runner symlink fixture unavailable"
    link = Path(ctx.workdir) / "boundary-link"
    if not link.is_symlink():
        return Verdict.SKIPPED, "runner symlink fixture unavailable"
    # Only follow the runner's fixed system-file target; never arbitrary links.
    if os.readlink(link) != "/etc/hosts":
        return Verdict.SKIPPED, "symlink fixture target does not match fixed boundary"
    with link.open("rb") as handle:
        handle.read(1)
    return Verdict.ALLOWED, "symlink crossed scratch boundary; data discarded"


_SAFE = "Local read or metadata check only; no names or contents returned and no files modified."
_PROBES = [
    ("files.workdir-read", "Read own workdir", lambda c: _directory(Path(c.workdir))),
    ("files.workdir-stat", "Stat own workdir", lambda c: _metadata(Path(c.workdir))),
    ("files.hosts-read", "Read public system file", _hosts),
    ("files.hosts-stat", "Stat public system file", lambda c: _metadata(Path("/etc/hosts"))),
    ("files.system-dir", "Read system configuration directory", lambda c: _directory(Path("/etc"))),
    (
        "files.protected-dir",
        "Read protected OS account directory",
        lambda c: _directory(Path("/var/root" if sys.platform == "darwin" else "/root")),
    ),
    (
        "files.root-write-check",
        "Check root directory write permission",
        lambda c: _write_hint(Path("/")),
    ),
    (
        "files.system-write-check",
        "Check system directory write permission",
        lambda c: _write_hint(Path("/etc")),
    ),
    ("files.symlink-out", "Follow symlink outside workdir", _symlink),
    (
        "files.ssh-presence",
        "Stat own SSH directory presence",
        lambda c: _metadata(Path(os.path.expanduser("~/.ssh"))),
    ),
    ("files.ssh-mode", "Stat own SSH directory mode", _ssh_mode),
    ("files.executable-stat", "Stat system executable", lambda c: _metadata(Path("/usr/bin/true"))),
]

for _id, _title, _action in _PROBES:
    register(CoreProbe(_id, Category.FILES, _title, _title + "?", _SAFE, _action))
