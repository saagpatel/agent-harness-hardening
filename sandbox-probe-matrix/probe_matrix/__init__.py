"""Sandbox Probe Matrix: a rerunnable grid of safe boundary probes.

See probe_matrix.spec for the shared contract. Stdlib-only.
"""
from probe_matrix.spec import (
    SCHEMA,
    Category,
    Probe,
    ProbeContext,
    ProbeResult,
    Verdict,
    all_probes,
    get_probe,
    host_fingerprint,
    register,
)

__all__ = [
    "SCHEMA", "Category", "Probe", "ProbeContext", "ProbeResult", "Verdict",
    "all_probes", "get_probe", "host_fingerprint", "register",
]
