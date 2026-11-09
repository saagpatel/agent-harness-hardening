from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from probe_matrix import cli
from probe_matrix.spec import all_probes


def test_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run", "--list"]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert len(rows) == len(all_probes())
    assert len(rows) >= 30
    assert all(len(row.split("\t")) == 3 for row in rows)


@pytest.mark.parametrize("flags", [["--dry-run", "run"], ["run", "--dry-run"]])
def test_json_stdout_and_table_stderr(flags: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(flags) == 0
    captured = capsys.readouterr()
    grid = json.loads(captured.out)
    assert grid["schema"] == "spm/v1"
    assert len(grid["results"]) == len(all_probes())
    assert len(grid["host_fingerprint"]) == 12
    assert all(row["verdict"] == "skipped" for row in grid["results"])
    assert "PROBE\tCATEGORY\tVERDICT" in captured.err


def test_single_probe_and_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    destination = tmp_path / "grid.json"
    assert (
        cli.main(["run", "--dry-run", "--probe", "files.hosts-read", "--out", str(destination)])
        == 0
    )
    grid = json.loads(destination.read_text())
    assert [row["probe_id"] for row in grid["results"]] == ["files.hosts-read"]
    assert "PROBE\tCATEGORY" in capsys.readouterr().out


def test_preflight_before_run_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    destination = tmp_path / "refused.json"
    monkeypatch.setenv("SPM_TARGET_HOST", "remote.invalid")
    assert cli.main(["run", "--out", str(destination), "--dry-run"]) == 2
    assert not destination.exists()
    captured = capsys.readouterr()
    assert "safety preflight" in captured.err
    assert "remote.invalid" not in captured.err


def test_unavailable_adapter_and_unknown_probe(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run", "--harness", "codex", "--mode", "workspace-write"]) == 0
    grid = json.loads(capsys.readouterr().out)
    assert all(row["detail"].startswith("adapter unavailable:") for row in grid["results"])
    with pytest.raises(SystemExit) as exc:
        cli.main(["run", "--probe", "unknown.invalid"])
    assert exc.value.code == 2


def test_report_absence_and_lazy_delegation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def absent(name: str) -> None:
        raise ModuleNotFoundError(name=name)

    monkeypatch.setattr(cli.importlib, "import_module", absent)
    assert cli.main(["report", "--baseline", "fixture.json", "--diff"]) == 2
    assert "reporter not installed" in capsys.readouterr().err
    seen: list[list[str]] = []

    def report(args: list[str]) -> int:
        seen.append(args)
        return 7

    monkeypatch.setattr(cli.importlib, "import_module", lambda name: SimpleNamespace(main=report))
    assert cli.main(["report", "--baseline", "fixture.json", "--diff"]) == 7
    assert seen == [["--baseline", "fixture.json", "--diff"]]


def test_report_internal_import_error_is_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(name: str) -> None:
        raise ModuleNotFoundError(name="missing_dependency")

    monkeypatch.setattr(cli.importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        cli.main(["report"])
