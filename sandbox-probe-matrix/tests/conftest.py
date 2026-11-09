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
