from __future__ import annotations

import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import pytest
from probe_matrix import safety
from probe_matrix.safety import UnsafeEnvironment, assert_safe_environment


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "localhost.",
        "127.0.0.1",
        "127.0.0.2:443",
        "[::1]:443",
        "::1",
        "https://localhost:443/",
        "tcp://[::1]:5432",
    ],
)
def test_loopback_selectors(value: str) -> None:
    assert_safe_environment({"SPM_TARGET_HOST": value}, [])


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "192.0.2.1",
        "https://example.com",
        "0.0.0.0",
        "[::]",
        "localhost.example.com",
        "https://foreign@localhost",
        "localhost:bad",
        "localhost/remote",
        "local\nhost",
        "unix:///foreign/socket",
        "",
        "[bad",
    ],
)
def test_remote_or_unproven_argument_refused(value: str) -> None:
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({}, ["--target-host", value])


@pytest.mark.parametrize(
    "key",
    [
        "HOST",
        "SPM_TARGET",
        "TARGET_URL",
        "DB_HOST",
        "SPM_TARGET_HOSTNAME",
    ],
)
def test_environment_remote_targets_refused_without_echo(key: str) -> None:
    with pytest.raises(UnsafeEnvironment) as exc:
        assert_safe_environment({key: "https://foreign.example.invalid"}, [])
    assert "foreign.example.invalid" not in str(exc.value)


def test_accounts_and_process_metadata() -> None:
    own = pwd.getpwuid(os.getuid()).pw_name
    assert_safe_environment({"SPM_TARGET_USER": own}, [])
    assert_safe_environment({"TARGET_ACCOUNT": str(os.getuid())}, [])
    assert_safe_environment(
        {"USER": "foreign", "HOSTNAME": "foreign.invalid", "HTTPS_PROXY": "https://proxy.invalid"},
        [],
    )
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({"SPM_TARGET_USER": "unowned-account.invalid"}, [])
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({}, ["--target-user=unowned-account.invalid"])


def test_arguments_cannot_override_unsafe_environment() -> None:
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({"TARGET_HOST": "remote.invalid"}, ["--host=localhost"])
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({}, ["--target-host"])


def test_home_must_be_owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert_safe_environment({"HOME": str(tmp_path)}, [])
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({"HOME": "relative-home"}, [])
    monkeypatch.setattr(
        safety.os, "stat", lambda path: SimpleNamespace(st_uid=os.getuid() + 1, st_mode=0o40700)
    )
    with pytest.raises(UnsafeEnvironment):
        assert_safe_environment({"HOME": str(tmp_path)}, [])
