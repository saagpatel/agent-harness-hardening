"""Tests never depend on inherited target selectors or public networking."""

from __future__ import annotations

import os

import pytest
from probe_matrix.safety import _kind


@pytest.fixture(autouse=True)
def local_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in os.environ:
        if _kind(key) is not None:
            monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def stable_install_id(monkeypatch, tmp_path_factory):
    # Give host_fingerprint a writable, isolated per-session id location so tests
    # never touch the real cache and never raise HostIdentityUnavailable.
    monkeypatch.setenv("SPM_SALT_DIR", str(tmp_path_factory.mktemp("spm-id")))
