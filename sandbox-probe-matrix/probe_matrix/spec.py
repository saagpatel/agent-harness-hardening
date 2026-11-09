"""Sandbox Probe Matrix — shared contract (the design spine).

Everything in the suite is built on these types. Workers implement probes,
runners, reporters and wings *against this module*; they do not change it.

Safety invariants that every probe MUST honour:
  * Read-only and non-destructive. A probe demonstrates *reachability* of a
    boundary; it never damages, persists, or exfiltrates anything.
  * Own machine and own accounts only. The runner refuses non-local / non-owned
    targets before any probe runs (see probe_matrix.safety).
  * No secret values ever leave a probe. The keychain wing is dry-run by
    default: it reports counts and categories, never values.
  * No real PII in committed output. Host identity is recorded only as a
    salted, truncated fingerprint (never a real path, name, email, or secret).

This module is stdlib-only and must stay that way.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import time
from typing import Callable, Dict, List, Optional, Protocol


SCHEMA = "spm/v1"


class Verdict(str, enum.Enum):
    """Outcome of a single probe in a single (harness, mode) cell."""

    ALLOWED = "allowed"   # the boundary was crossable (reachability demonstrated)
    BLOCKED = "blocked"   # the boundary held
    ERROR = "error"       # the probe could not run to a conclusion
    SKIPPED = "skipped"   # not applicable / opted out (e.g. keychain wing off)


class Category(str, enum.Enum):
    FILES = "files"
    SOCKETS = "sockets"
    NETWORK = "network"
    APP_LAUNCH = "app_launch"
    TEMP = "temp"
    WORKTREE = "worktree"
    KEYCHAIN = "keychain"


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    """Score of one probe in one cell."""

    probe_id: str
    category: Category
    verdict: Verdict
    detail: str = ""              # short, PII-free human note on what was observed
    harness: str = "shell"        # e.g. "shell", "claude-code", "codex"
    mode: str = "default"         # harness-specific sandbox/permission mode
    elapsed_ms: int = 0

    def to_json(self) -> Dict:
        return {
            "probe_id": self.probe_id,
            "category": self.category.value,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "harness": self.harness,
            "mode": self.mode,
            "elapsed_ms": self.elapsed_ms,
        }


class Probe(Protocol):
    """A declarative boundary probe.

    Implementations live in probes/<category>/ and register via @register.
    `run()` performs the safe action and returns a verdict. It must never raise
    for an expected "blocked" outcome (a blocked syscall is a result, not an
    error); it returns Verdict.ERROR only when it cannot reach a conclusion.
    """

    id: str
    category: Category
    title: str
    description: str   # the single question this probe asks
    safety_note: str   # why this action is safe (no harm, no persistence, no leak)

    def run(self, ctx: "ProbeContext") -> ProbeResult: ...


@dataclasses.dataclass
class ProbeContext:
    """Runtime context handed to each probe.

    `dry_run` forces enumerate-only behaviour (the keychain wing honours it and
    is dry-run by default regardless). `harness`/`mode` label the cell. `workdir`
    is a scratch directory the probe may use and that the runner cleans up.
    """

    harness: str = "shell"
    mode: str = "default"
    dry_run: bool = False
    workdir: str = ""
    extra: Dict[str, str] = dataclasses.field(default_factory=dict)


# ---- registry -----------------------------------------------------------------

_REGISTRY: "Dict[str, Probe]" = {}


def register(probe: Probe) -> Probe:
    """Register a probe instance by id. Duplicate ids are a hard error."""
    if probe.id in _REGISTRY:
        raise ValueError(f"duplicate probe id: {probe.id}")
    _REGISTRY[probe.id] = probe
    return probe


def all_probes() -> "List[Probe]":
    return [p for _, p in sorted(_REGISTRY.items())]


def get_probe(probe_id: str) -> "Optional[Probe]":
    return _REGISTRY.get(probe_id)


def clear_registry() -> None:
    """Test helper: empty the registry."""
    _REGISTRY.clear()


# ---- helpers ------------------------------------------------------------------

class HostIdentityUnavailable(RuntimeError):
    """No private per-install identity could be read, created, or provided."""


def _install_id() -> bytes:
    """A stable, private, random per-install identity, kept OUT of reports/repo.

    The committed baseline fingerprint is a hash of this id, unknown to anyone
    reading the baseline. The id is random — NOT derived from any hardware or OS
    value — so it:
      * survives OS/kernel upgrades (the same install keeps the same identity);
      * distinguishes two installs even on identical hardware/OS; and
      * has no brute-force surface (there is no hardware input to recover).
    `SPM_INSTALL_ID` (hex) supplies it directly; `SPM_SALT_DIR` overrides the
    persistence directory (both used by tests and read-only sandboxes). If no id
    can be read, created, or provided, this raises HostIdentityUnavailable rather
    than silently emitting a weak fingerprint.
    """
    import os
    import pathlib

    provided = os.environ.get("SPM_INSTALL_ID")
    if provided:
        try:
            return bytes.fromhex(provided)
        except ValueError as exc:
            raise HostIdentityUnavailable("SPM_INSTALL_ID is not valid hex") from exc

    base = os.environ.get("SPM_SALT_DIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "sandbox-probe-matrix"
    )
    path = pathlib.Path(base) / "install-id"
    try:
        if path.exists():
            data = path.read_bytes()
            if data:
                return data
        path.parent.mkdir(parents=True, exist_ok=True)
        import secrets

        ident = secrets.token_bytes(16)
        path.write_bytes(ident)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return ident
    except OSError as exc:
        raise HostIdentityUnavailable(
            "no private install id available: set SPM_SALT_DIR to a writable "
            "private directory or SPM_INSTALL_ID to a hex id"
        ) from exc


def host_fingerprint() -> str:
    """A truncated, non-reversible id for the install a run came from.

    It is the hash of a stable, private, random per-install id (see `_install_id`),
    not of any hardware or OS value — so an OS upgrade keeps the identity stable,
    two installs on the same machine differ, and the committed 12-hex digest cannot
    be reversed to anything about the host. Raises HostIdentityUnavailable when no
    private id can be obtained, rather than emitting a weak fingerprint.
    """
    return hashlib.sha256(_install_id()).hexdigest()[:12]


def now_ms() -> int:
    return int(time.time() * 1000)
