"""Fixed public boundary checks only; never use target/proxy environment values.

DNS necessarily sends resolver traffic; no application payload, TLS handshake,
HTTP request or credentials are sent. A failed offline self-check is SKIPPED,
not evidence that a sandbox denied egress. Refused/permission errors are BLOCKED.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys

from probe_matrix.spec import Category, ProbeContext, Verdict, register
from probes.core._base import TIMEOUT, CoreProbe, Outcome

_DNS_CHECK = """import socket, sys
try:
    socket.getaddrinfo('example.com', 443, type=socket.SOCK_STREAM)
except PermissionError:
    sys.exit(3)
except OSError:
    sys.exit(2)
"""


def _dns(_: ProbeContext) -> Outcome:
    # getaddrinfo has no portable deadline: isolate it in a killable child.
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", _DNS_CHECK],
            timeout=TIMEOUT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Verdict.SKIPPED, "DNS self-check timed out; offline or resolver unavailable"
    if result.returncode == 0:
        return Verdict.ALLOWED, "public DNS lookup succeeded; addresses discarded"
    if result.returncode == 3:
        return Verdict.BLOCKED, "DNS lookup permission denied"
    return Verdict.SKIPPED, "DNS self-check failed; offline or resolver unavailable"


def _tcp(family: socket.AddressFamily, host: str) -> Outcome:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(TIMEOUT)
            client.connect((host, 443))
    except TimeoutError:
        return Verdict.SKIPPED, "egress self-check timed out; offline or filtering undetermined"
    return Verdict.ALLOWED, "public TCP connection closed; no application payload sent"


def _env(names: tuple[str, ...]) -> Outcome:
    present = any(bool(os.environ.get(name)) for name in names)
    if present:
        return Verdict.ALLOWED, "proxy configuration present; values unread by output"
    return Verdict.SKIPPED, "proxy configuration absent"


_SAFE = (
    "Fixed public boundary check; 2s cap, no application data, no addresses or env values returned."
)
for _id, _title, _action in [
    ("network.dns-public", "Resolve public DNS name", _dns),
    ("network.tcp-ipv4", "Reach public IPv4 TLS port", lambda c: _tcp(socket.AF_INET, "1.1.1.1")),
    (
        "network.tcp-ipv6",
        "Reach public IPv6 TLS port",
        lambda c: _tcp(socket.AF_INET6, "2606:4700:4700::1111"),
    ),
    (
        "network.proxy-env",
        "Detect proxy configuration",
        lambda c: _env(
            ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
        ),
    ),
    (
        "network.no-proxy-env",
        "Detect proxy bypass configuration",
        lambda c: _env(("NO_PROXY", "no_proxy")),
    ),
]:
    register(CoreProbe(_id, Category.NETWORK, _title, _title + "?", _SAFE, _action))
