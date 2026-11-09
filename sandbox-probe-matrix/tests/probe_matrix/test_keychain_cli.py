"""The keychain wing's opt-in must be reachable through the CLI (Sol round-2 #3).

Default CLI runs skip it; `--enable-keychain` reaches metadata enumeration. The
enumeration itself is mocked so the test never touches a real keychain.
"""
from __future__ import annotations

import json

import pytest

from probe_matrix import cli
import probes.keychain as kc


def _run(tmp_path, *extra):
    out = tmp_path / "grid.json"
    rc = cli.main(["run", "--harness", "shell", "--mode", "default",
                   "--out", str(out), *extra])
    assert rc == 0
    return {r["probe_id"]: r for r in json.loads(out.read_text())["results"]}


def test_default_cli_run_skips_keychain(tmp_path):
    rows = _run(tmp_path)
    assert rows["keychain.metadata-reach"]["verdict"] == "skipped"


def test_enable_keychain_reaches_enumeration(tmp_path, monkeypatch):
    calls = {"ran": False}

    class _Fake:
        returncode = 0
        # one generic + one internet password class line; no values.
        stdout = 'class: "genp"\nclass: "inet"\n'

    def fake_run(cmd, **kwargs):
        calls["ran"] = True
        assert "-d" not in cmd  # never request secret data
        return _Fake()

    monkeypatch.setattr(kc.sys, "platform", "darwin")
    monkeypatch.setattr(kc.subprocess, "run", fake_run)
    rows = _run(tmp_path, "--enable-keychain")
    row = rows["keychain.metadata-reach"]
    assert calls["ran"] is True
    assert row["verdict"] == "allowed"
    assert "generic_password=1" in row["detail"] and "internet_password=1" in row["detail"]
    # Never leak a secret value.
    assert "sentinel" not in row["detail"].lower()
