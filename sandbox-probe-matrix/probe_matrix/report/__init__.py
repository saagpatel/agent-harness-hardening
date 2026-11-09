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
        clean.append({'schema': SCHEMA, 'generated_at': float(grid['generated_at']),
                      'harness': harness, 'mode': mode, 'host_fingerprint': fingerprint,
                      'results': results})
    return clean


def save_baseline(grids: list[Grid], path: str | Path) -> None:
    Path(path).write_text(json.dumps(_clean(grids), indent=2, allow_nan=False) + '\n', encoding='utf-8')


def load_baseline(path: str | Path) -> list[Grid]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError('baseline must be a list of grids')
    return _clean(data)


def _cells(grids: list[Grid]) -> dict[CellKey, Verdict]:
    return {(r['probe_id'], g['harness'], g['mode']): Verdict(r['verdict'])
            for g in _clean(grids) for r in g['results']}


def diff_against_baseline(grids: list[Grid], baseline: list[Grid]) -> DiffResult:
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
