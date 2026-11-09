"""Refuse explicit remote or foreign-account target selectors, without resolving DNS.

There is no configurable probe destination: core endpoints are fixed boundary
checks. Still reject inherited target selectors so a remote execution wrapper
cannot silently change the meaning of a local run. Recognized selectors are
HOST, *_HOST, TARGET, *_TARGET, *_TARGET_URL, *_TARGET_HOSTNAME,
TARGET_USER/ACCOUNT and their prefixed variants, REMOTE_USER/ACCOUNT, and the
equivalent --kebab-case arguments. HOSTNAME, USER, LOGNAME and proxy variables
describe the current process/transport, not probe targets, and are ignored.
Unknown CLI options are separately rejected by argparse. Do not add configurable
endpoints without extending this preflight and its tests.
"""

from __future__ import annotations

import ipaddress
import os
import pwd
import stat
import sys
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit


class UnsafeEnvironment(ValueError):
    """An explicit target selector cannot be proven local and owned."""


def _kind(name: str) -> str | None:
    name = name.upper().replace("-", "_")
    if name in {"USER", "LOGNAME", "HOSTNAME"}:
        return None
    if name in {"TARGET_USER", "TARGET_ACCOUNT", "REMOTE_USER", "REMOTE_ACCOUNT"} or name.endswith(
        ("_TARGET_USER", "_TARGET_ACCOUNT", "_REMOTE_USER", "_REMOTE_ACCOUNT")
    ):
        return "account"
    if name in {"HOST", "TARGET", "TARGET_URL", "TARGET_HOSTNAME"} or name.endswith(
        ("_HOST", "_TARGET", "_TARGET_URL", "_TARGET_HOSTNAME")
    ):
        return "host"
    return None


def _local_host(value: str) -> bool:
    if any(character.isspace() for character in value):
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        pass
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        host = parsed.hostname
        # Credentials in a target URL select an account as well as a host.
        if parsed.username is not None or parsed.password is not None:
            return False
        if parsed.scheme and parsed.scheme not in {"http", "https", "tcp", "ssh"}:
            return False
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return False
        _ = parsed.port  # reject malformed ports
        if host is None:
            return False
        if host.lower().rstrip(".") == "localhost":
            return True
        # Do not resolve aliases: a local-looking name can resolve remotely.
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_safe_environment(
    environ: Mapping[str, str] | None = None,
    args: Sequence[str] | None = None,
) -> None:
    """Raise with a PII-free message before running even a dry-run cell.

    Only the actual OS account name or uid is accepted for account selectors;
    environment USER/LOGNAME cannot assert ownership. Empty selectors are ignored.
    A non-network target string is refused too, rather than guessing its meaning.
    Neither the selector's name nor its value is echoed in an error.
    """
    env = os.environ if environ is None else environ
    argv = list(sys.argv[1:] if args is None else args)
    # expanduser() supplies the SSH metadata target. A forged HOME must not
    # redirect even that stat-only probe into a different account's directory.
    if "HOME" in env:
        try:
            home = env["HOME"]
            if not os.path.isabs(home):
                raise UnsafeEnvironment("refusing target: home ownership is not established")
            info = os.stat(home)
            if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode):
                raise UnsafeEnvironment("refusing target: home ownership is not established")
        except OSError:
            raise UnsafeEnvironment("refusing target: home ownership is not established") from None
    selectors = list(env.items())
    for index, token in enumerate(argv):
        if not token.startswith("--"):
            continue
        name, sep, value = token[2:].partition("=")
        if _kind(name) is not None:
            if not sep:
                value = argv[index + 1] if index + 1 < len(argv) else ""
            if not value or value.startswith("--"):
                raise UnsafeEnvironment("target selector requires an explicit local value")
            selectors.append((name, value))
    for name, value in selectors:
        kind = _kind(name)
        if kind is None or not value:
            continue
        if kind == "host" and not _local_host(value):
            raise UnsafeEnvironment("refusing target: only explicit loopback hosts are owned/local")
        if kind == "account":
            try:
                account = pwd.getpwuid(os.getuid()).pw_name
            except KeyError:
                raise UnsafeEnvironment(
                    "refusing target: account ownership is not established"
                ) from None
            if value not in {account, str(os.getuid())}:
                raise UnsafeEnvironment("refusing target: account ownership is not established")
