"""Integration: the real CLI grid must flow through the real reporter.

Guards against the two regressions Sol flagged on PR #1: the report subcommand
being unreachable, and the ISO-8601 `generated_at` the CLI emits being rejected
by the reporter's timestamp handling.
"""
from __future__ import annotations

import json
from pathlib import Path

from probe_matrix import cli
from probe_matrix import report


def _make_grid(tmp_path: Path) -> Path:
    out = tmp_path / "grid.json"
    rc = cli.main(["run", "--harness", "shell", "--mode", "default", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    # The CLI emits an ISO-8601 string timestamp (the shape the reporter must accept).
    assert isinstance(data["generated_at"], str)
    return out


def test_cli_grid_renders_and_diffs(tmp_path: Path, capsys) -> None:
    grid = _make_grid(tmp_path)

    # 1) report subcommand is reachable and renders a terminal grid.
    assert cli.main(["report", "--grid", str(grid)]) == 0
    assert capsys.readouterr().out.strip() != ""

    # 2) real CLI JSON flows into the reporter API without a timestamp ValueError.
    grids = report._load_grids([str(grid)])
    report.render_terminal(grids)
    report.render_html(grids)

    # 3) save a baseline and diff against it through the CLI.
    base = tmp_path / "base.json"
    assert cli.main(["report", "--grid", str(grid), "--save-baseline", str(base)]) == 0
    assert cli.main(["report", "--grid", str(grid), "--baseline", str(base), "--diff"]) == 0
