"""Local sockets: connect and close, or bind loopback without listening."""

from __future__ import annotations

import socket
import stat
from pathlib import Path

from probe_matrix.spec import Category, Verdict, register
from probes.core._base import TIMEOUT, CoreProbe, Outcome


def _unix(path: str) -> Outcome:
    if not stat.S_ISSOCK(Path(path).stat().st_mode):
        return Verdict.SKIPPED, "endpoint is not a socket"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT)
        client.connect(path)
    return Verdict.ALLOWED, "local socket connected and closed; no payload sent"


def _bind(family: socket.AddressFamily, host: str) -> Outcome:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.settimeout(TIMEOUT)
        server.bind((host, 0))
    return Verdict.ALLOWED, "ephemeral loopback port bound and released; never listened"


def _daemon(port: int) -> Outcome:
    # Connecting is itself the listening self-check; do not scan or send auth/data.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT)
        client.connect(("127.0.0.1", port))
    return Verdict.ALLOWED, "local daemon accepted connection; closed without payload"


_SAFE = "Fixed local endpoint only; 2s timeout, immediate close, no application payload or auth."
for _id, _title, _action in [
    (
        "sockets.unix-container",
        "Reach local container socket",
        lambda c: _unix("/var/run/docker.sock"),
    ),
    (
        "sockets.unix-print",
        "Reach local printing socket",
        lambda c: _unix("/var/run/cups/cups.sock"),
    ),
    (
        "sockets.unix-database",
        "Reach local database socket",
        lambda c: _unix("/var/run/postgresql/.s.PGSQL.5432"),
    ),
    ("sockets.bind-ipv4", "Bind IPv4 loopback port", lambda c: _bind(socket.AF_INET, "127.0.0.1")),
    ("sockets.bind-ipv6", "Bind IPv6 loopback port", lambda c: _bind(socket.AF_INET6, "::1")),
    ("sockets.daemon-print", "Reach local printing TCP port", lambda c: _daemon(631)),
    ("sockets.daemon-database", "Reach local database TCP port", lambda c: _daemon(5432)),
    ("sockets.daemon-cache", "Reach local cache TCP port", lambda c: _daemon(6379)),
]:
    register(CoreProbe(_id, Category.SOCKETS, _title, _title + "?", _SAFE, _action))
