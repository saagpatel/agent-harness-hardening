"""Probe registration entry point for the matrix.

Importing this package registers the core probes and the three wings
(Shared Temp Leak, Worktree Hook Bleed, Keychain Reach). The keychain wing is
dry-run / opt-in and reports SKIPPED unless explicitly enabled.
"""
from __future__ import annotations


def register_all() -> None:
    """Import every probe module so each registers itself exactly once."""
    from probe_matrix.probes import core  # noqa: F401  (core shim -> probes.core.*)
    import probes.temp  # noqa: F401
    import probes.worktree  # noqa: F401
    import probes.keychain  # noqa: F401
