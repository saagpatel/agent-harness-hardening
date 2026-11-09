"""Offline presentation and comparison of probe-matrix grids."""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
import json
from pathlib import Path
import re
import sys
from typing import Any, Literal

from probe_matrix.spec import Category, SCHEMA, Verdict

Grid = dict[str, Any]
CellKey = tuple[str, str, str]
Classification = Literal['flipped_open', 'flipped_closed', 'new', 'removed', 'unchanged', 'changed']
LEGEND = 'A red cell is a finding to act on, not a resolved issue.'
_TOKEN = re.compile(r'^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$')


@dataclass(frozen=True)
class DiffCell:
    key: CellKey
    before: Verdict | None
    after: Verdict | None
    classification: Classification


@dataclass(frozen=True)
class DiffResult:
    cells: list[DiffCell]


def _token(value: Any) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError('invalid report identifier')
    return value


def _coerce_ts(value: Any) -> float:
    """Accept either an epoch float/int or an ISO 8601 string (what the CLI emits)."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            from datetime import datetime

            return datetime.fromisoformat(value).timestamp()
    raise ValueError('invalid generated_at timestamp')


def _clean(grids: list[Grid]) -> list[Grid]:
    """Validate grid identity and discard unneeded free-text details."""
    clean: list[Grid] = []
    seen: set[CellKey] = set()
    pairs: set[tuple[str, str]] = set()
    for grid in grids:
        if grid['schema'] != SCHEMA:
            raise ValueError('unsupported grid schema')
        harness, mode = _token(grid['harness']), _token(grid['mode'])
        if (harness, mode) in pairs:
            raise ValueError('duplicate harness/mode grid')
        pairs.add((harness, mode))
        fingerprint = grid['host_fingerprint']
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{12}', fingerprint):
            raise ValueError('invalid host fingerprint')
        results: list[Grid] = []
        for result in grid['results']:
            probe_id = _token(result['probe_id'])
            if result['harness'] != harness or result['mode'] != mode:
                raise ValueError('cell does not match grid')
            key = (probe_id, harness, mode)
            if key in seen:
                raise ValueError('duplicate cell')
            seen.add(key)
            results.append({'probe_id': probe_id, 'category': Category(result['category']).value,
                            'verdict': Verdict(result['verdict']).value, 'detail': '',
                            'harness': harness, 'mode': mode,
                            'elapsed_ms': int(result['elapsed_ms'])})
        clean.append({'schema': SCHEMA, 'generated_at': _coerce_ts(grid['generated_at']),
                      'harness': harness, 'mode': mode, 'host_fingerprint': fingerprint,
                      'results': results})
    return clean


def save_baseline(grids: list[Grid], path: str | Path) -> None:
    Path(path).write_text(json.dumps(_clean(grids), indent=2, allow_nan=False) + '\n', encoding='utf-8')


def _atomic_save_baseline(grids: list[Grid], path: str | Path) -> None:
    """Validate and render first, then replace the target in one atomic rename so a
    failure or crash cannot destroy the previous baseline."""
    import os
    import tempfile

    target = Path(path)
    payload = json.dumps(_clean(grids), indent=2, allow_nan=False) + '\n'
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.spm-baseline-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(payload)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_baseline(path: str | Path) -> list[Grid]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError('baseline must be a list of grids')
    return _clean(data)


def _cells(grids: list[Grid]) -> dict[CellKey, Verdict]:
    return {(r['probe_id'], g['harness'], g['mode']): Verdict(r['verdict'])
            for g in _clean(grids) for r in g['results']}


def _fingerprints(grids: list[Grid]) -> dict[tuple[str, str], str]:
    return {(_token(g['harness']), _token(g['mode'])): g['host_fingerprint'] for g in grids}


def diff_against_baseline(grids: list[Grid], baseline: list[Grid]) -> DiffResult:
    # A baseline is only comparable to a rerun from the SAME machine. Comparing a
    # blocked baseline from machine A against an allowed run from machine B would
    # otherwise be reported as a flipped_open sandbox regression, when it is only
    # an environmental difference. Refuse a cross-host comparison for any shared
    # harness/mode grid rather than emit a false finding.
    cur_fp, base_fp = _fingerprints(grids), _fingerprints(baseline)
    for cell_key in cur_fp.keys() & base_fp.keys():
        if cur_fp[cell_key] != base_fp[cell_key]:
            raise ValueError(
                'cross-host baseline comparison refused: host fingerprints differ for '
                f'harness/mode {cell_key}; compare a rerun from the same machine'
            )
    current, previous = _cells(grids), _cells(baseline)
    cells: list[DiffCell] = []
    for key in sorted(current.keys() | previous.keys()):
        before, after = previous.get(key), current.get(key)
        kind: Classification
        if before is None:
            kind = 'new'
        elif after is None:
            kind = 'removed'
        elif before == after:
            kind = 'unchanged'
        elif before == Verdict.BLOCKED and after == Verdict.ALLOWED:
            kind = 'flipped_open'
        elif before == Verdict.ALLOWED and after == Verdict.BLOCKED:
            kind = 'flipped_closed'
        else:
            kind = 'changed'
        cells.append(DiffCell(key, before, after, kind))
    return DiffResult(cells)


def _table(headers: tuple[str, ...], rows: list[tuple[str, ...]], red: set[int] | None = None) -> str:
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))]
    def line(row: tuple[str, ...]) -> str:
        return ' | '.join(value.ljust(widths[i]) for i, value in enumerate(row)).rstrip()
    lines = [line(headers), '-+-'.join('-' * width for width in widths)]
    for i, row in enumerate(rows):
        text = line(row)
        if red and i in red and sys.stdout.isatty():
            text = '\x1b[31m' + text + '\x1b[0m'
        lines.append(text)
    return '\n'.join(lines)


def render_terminal(grids: list[Grid]) -> str:
    sections: list[str] = []
    for grid in _clean(grids):
        rows = [(r['probe_id'], r['category'], r['verdict']) for r in grid['results']]
        sections.append(f"{grid['harness']} / {grid['mode']} ({grid['host_fingerprint']})\n" +
                        _table(('Probe', 'Category', 'Verdict'), rows))
    return '\n\n'.join(sections)


def render_diff_terminal(diff: DiffResult) -> str:
    rows = [(c.key[0], c.key[1], c.key[2], c.before.value if c.before else '-',
             c.after.value if c.after else '-', c.classification) for c in diff.cells]
    red = {i for i, c in enumerate(diff.cells) if c.classification == 'flipped_open'}
    return _table(('Probe', 'Harness', 'Mode', 'Before', 'After', 'Change'), rows, red) + '\n' + LEGEND


def _document(body: str) -> str:
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Probe matrix</title><style>body{font-family:sans-serif;margin:2rem}'
            'table{border-collapse:collapse;margin-bottom:2rem}th,td{border:1px solid #777;'
            'padding:.4rem;text-align:left}.flipped-open{background:#a00;color:#fff}'
            '</style></head><body><h1>Probe matrix</h1>' + body +
            '<p>' + LEGEND + '</p></body></html>')


def _html_table(headers: tuple[str, ...], rows: list[tuple[tuple[str, ...], bool]]) -> str:
    head = ''.join(f'<th scope="col">{escape(h)}</th>' for h in headers)
    body = ''.join('<tr' + (' class="flipped-open"' if red else '') + '>' +
                   ''.join(f'<td>{escape(value)}</td>' for value in row) + '</tr>'
                   for row, red in rows)
    return '<table><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>'


def render_html(grids: list[Grid]) -> str:
    sections: list[str] = []
    for grid in _clean(grids):
        title = escape(f"{grid['harness']} / {grid['mode']} ({grid['host_fingerprint']})")
        rows = [((r['probe_id'], r['category'], r['verdict']), False) for r in grid['results']]
        sections.append('<h2>' + title + '</h2>' + _html_table(('Probe', 'Category', 'Verdict'), rows))
    return _document(''.join(sections))


def render_diff_html(diff: DiffResult) -> str:
    rows = [((c.key[0], c.key[1], c.key[2], c.before.value if c.before else '-',
              c.after.value if c.after else '-', c.classification), c.classification == 'flipped_open')
            for c in diff.cells]
    return _document(_html_table(('Probe', 'Harness', 'Mode', 'Before', 'After', 'Change'), rows))


def _load_grids(paths: list[str]) -> list[Grid]:
    grids: list[Grid] = []
    for p in paths:
        data = json.loads(Path(p).read_text(encoding='utf-8'))
        grids.extend(data if isinstance(data, list) else [data])
    return grids


def _aliases_any(target: str, others: list[str]) -> bool:
    """True if `target` resolves to the same file as any of `others` (following
    symlinks/hard links where the paths exist)."""
    import os

    def key(path: str):
        real = os.path.realpath(path)
        try:
            st = os.stat(path)
            return (st.st_dev, st.st_ino)  # same inode = same file (hard link/symlink)
        except OSError:
            return ("path", real)

    tk = key(target)
    return any(key(o) == tk for o in others)


def main(argv: list[str] | None = None) -> int:
    """`spm report` entry point.

    Render one or more run grids as a terminal table and/or HTML, optionally
    saving a baseline or diffing against one (flipped-open cells shown red).
    """
    import argparse

    parser = argparse.ArgumentParser(prog='spm report')
    parser.add_argument('--grid', action='append', default=[], metavar='FILE',
                        help='a run grid JSON (repeatable); omit to read one from stdin')
    parser.add_argument('--baseline', metavar='FILE', help='baseline grid(s) to compare against')
    parser.add_argument('--diff', action='store_true', help='show the diff vs the baseline')
    parser.add_argument('--save-baseline', metavar='FILE', help='save the given grids as a baseline')
    parser.add_argument('--html', metavar='FILE', help='also write a static HTML report here')
    parsed = parser.parse_args(argv)

    if parsed.grid:
        grids = _load_grids(parsed.grid)
    else:
        grids = _load_grids(['/dev/stdin'])

    # Compute EVERYTHING (comparison + rendered output) before writing any
    # baseline, so --baseline and --save-baseline may name the same file: a
    # cross-host or load failure raises here, leaving the existing baseline intact.
    previous = None
    if parsed.diff or parsed.baseline:
        if not parsed.baseline:
            print('--diff requires --baseline FILE', file=sys.stderr)
            return 2
        previous = load_baseline(parsed.baseline)

    try:
        if previous is not None:
            diff = diff_against_baseline(grids, previous)  # may raise (cross-host)
            terminal_out = render_diff_terminal(diff)
            html_out = render_diff_html(diff) if parsed.html else None
        else:
            terminal_out = render_terminal(grids)
            html_out = render_html(grids) if parsed.html else None
    except ValueError as exc:
        # Comparison failed before any baseline was written: the existing baseline
        # is left intact.
        print(f'report: {exc}', file=sys.stderr)
        return 2

    # Refuse an HTML destination that aliases an input grid or either baseline path
    # (directly or via an existing symlink/hard link): writing HTML there would
    # destroy the saved comparison state.
    if parsed.html:
        protected = [p for p in ([parsed.baseline, parsed.save_baseline] + list(parsed.grid)) if p]
        refuse = _aliases_any(parsed.html, protected)
        # When the grid was read from stdin (no --grid), a redirect `< run.json` makes
        # the input the regular file behind fd 0; guard it so --html can't truncate it.
        if not refuse and not parsed.grid:
            import os as _os

            try:
                in_st = _os.fstat(0)
                html_st = _os.stat(parsed.html)
                refuse = (in_st.st_ino != 0 and (in_st.st_dev, in_st.st_ino) == (html_st.st_dev, html_st.st_ino))
            except OSError:
                refuse = False
        if refuse:
            print('report: --html path aliases a grid or baseline file; refusing', file=sys.stderr)
            return 2

    # Deliver ALL requested output — stdout and HTML — and flush it BEFORE replacing
    # the baseline. If any write fails, the command fails with the old baseline still
    # intact, so a retry still sees the unreported regression (no silent data loss).
    sys.stdout.write(terminal_out + '\n')
    sys.stdout.flush()
    if html_out is not None and parsed.html:
        Path(parsed.html).write_text(html_out, encoding='utf-8')

    # Reports succeeded: only now persist the new baseline, atomically.
    if parsed.save_baseline:
        _atomic_save_baseline(grids, parsed.save_baseline)
    return 0
