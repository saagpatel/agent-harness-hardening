"""The spm command: list core probes, run one cell, or delegate reporting."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from probe_matrix.runner import available_harnesses, modes_for, run_cell
from probe_matrix.safety import UnsafeEnvironment, assert_safe_environment
from probe_matrix.spec import SCHEMA, all_probes, get_probe, host_fingerprint


def _report(argv: list[str]) -> int:
    try:
        reporter = importlib.import_module("probe_matrix.report")
    except ModuleNotFoundError as exc:
        if exc.name != "probe_matrix.report":
            raise
        print("reporter not installed: probe_matrix.report is unavailable", file=sys.stderr)
        return 2
    entry = getattr(reporter, "main", None)
    if not callable(entry):
        print("reporter not installed: report.main(argv) is unavailable", file=sys.stderr)
        return 2
    return cast(Callable[[list[str]], int], entry)(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # Forward report arguments verbatim, including future reporter options.
    if args and args[0] == "report":
        return _report(args[1:])
    parser = argparse.ArgumentParser(prog="spm")
    parser.add_argument("--dry-run", action="store_true", help="enumerate without probe actions")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="list probes or run a harness/mode cell")
    run.add_argument("--list", action="store_true")
    run.add_argument("--harness", choices=available_harnesses(), default="shell")
    run.add_argument("--mode", help="default: shell/default, claude-code/default, codex/read-only")
    run.add_argument("--probe", help="run a single registered probe ID")
    run.add_argument("--out", type=Path, help="write grid JSON here; otherwise JSON goes to stdout")
    run.add_argument("--dry-run", action="store_true", dest="run_dry_run")
    commands.add_parser("report", help="delegate to optional reporter")
    parsed = parser.parse_args(args)
    from probe_matrix.probes import register_all

    register_all()  # core probes + the three wings

    if parsed.list:
        for probe in all_probes():
            print(f"{probe.id}\t{probe.category.value}\t{probe.title}")
        return 0
    mode = parsed.mode or modes_for(parsed.harness)[0]
    if mode not in modes_for(parsed.harness):
        parser.error("unknown mode for selected harness")
    probes = all_probes()
    if parsed.probe:
        probe = get_probe(parsed.probe)
        if probe is None:
            parser.error("unknown probe ID; use run --list")
        probes = [probe]
    try:
        assert_safe_environment(args=args)
        results = run_cell(parsed.harness, mode, probes, parsed.dry_run or parsed.run_dry_run)
        grid = {
            "schema": SCHEMA,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "harness": parsed.harness,
            "mode": mode,
            "host_fingerprint": host_fingerprint(),
            "results": [result.to_json() for result in results],
        }
        payload = json.dumps(grid, indent=2) + "\n"
        if parsed.out is not None:
            parsed.out.write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload)
    except UnsafeEnvironment as exc:
        print(f"safety preflight: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print(
            "run failed: local fixture or output unavailable; details suppressed", file=sys.stderr
        )
        return 2
    # Keep stdout machine-readable when it carries JSON.
    table = sys.stdout if parsed.out is not None else sys.stderr
    print("PROBE\tCATEGORY\tVERDICT\tDETAIL", file=table)
    for result in results:
        print(
            f"{result.probe_id}\t{result.category.value}\t{result.verdict.value}\t{result.detail}",
            file=table,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
