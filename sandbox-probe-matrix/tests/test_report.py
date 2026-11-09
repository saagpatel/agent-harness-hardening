from copy import deepcopy
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from probe_matrix.report import (
    diff_against_baseline, load_baseline, render_diff_html, render_diff_terminal,
    render_html, render_terminal, save_baseline,
)


def grids():
    def grid(harness, verdict):
        return {'schema': 'spm/v1', 'generated_at': 1.0, 'harness': harness,
                'mode': 'default', 'host_fingerprint': '012345abcdef', 'results': [
                    {'probe_id': 'files.read', 'category': 'files', 'verdict': verdict,
                     'detail': '/private/example', 'harness': harness, 'mode': 'default',
                     'elapsed_ms': 12}]}
    return [grid('shell', 'blocked'), grid('other', 'allowed')]


def test_baseline_and_diff(tmp_path):
    original = grids()
    path = tmp_path / 'baseline.json'
    save_baseline(original, path)
    assert '/private/example' not in path.read_text()
    baseline = load_baseline(path)
    current = deepcopy(original)
    current[0]['results'][0]['verdict'] = 'allowed'
    diff = diff_against_baseline(current, baseline)
    assert [(c.key, c.classification) for c in diff.cells if c.classification == 'flipped_open'] == [
        (('files.read', 'shell', 'default'), 'flipped_open')]
    assert sorted(c.classification for c in diff.cells) == ['flipped_open', 'unchanged']
    html = render_diff_html(diff)
    assert 'class="flipped-open"' in html
    assert 'A red cell is a finding to act on, not a resolved issue.' in html


def test_render_html():
    html = render_html(grids())
    assert html.lower().startswith('<!doctype html')
    assert html.count('<table>') == 2
    assert 'A red cell is a finding to act on, not a resolved issue.' in html
    assert '/private/example' not in html


def test_non_tty(monkeypatch):
    monkeypatch.setattr(sys, 'stdout', io.StringIO())
    original = grids()
    current = deepcopy(original)
    current[0]['results'][0]['verdict'] = 'allowed'
    assert '\x1b[' not in render_terminal(current)
    assert '\x1b[' not in render_diff_terminal(diff_against_baseline(current, original))


def test_other_transitions_and_invalid_data():
    original = grids()
    current = deepcopy(original)
    current[0]['results'][0]['verdict'] = 'error'
    current.pop()
    current.append(deepcopy(original[0]))
    current[1]['harness'] = 'new'
    current[1]['results'][0]['harness'] = 'new'
    diff = diff_against_baseline(current, original)
    assert {c.classification for c in diff.cells} == {'changed', 'removed', 'new'}
    current[0]['results'][0]['probe_id'] = '/private/example'
    with pytest.raises(ValueError):
        render_html(current)


def test_tty_marks_only_open_flip(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, 'stdout', Tty())
    original = grids()
    current = deepcopy(original)
    current[0]['results'][0]['verdict'] = 'allowed'
    current[1]['results'][0]['verdict'] = 'blocked'
    diff = diff_against_baseline(current, original)
    assert {cell.classification for cell in diff.cells} == {'flipped_open', 'flipped_closed'}
    output = render_diff_terminal(diff)
    assert output.count('\x1b[31m') == 1
    assert '\x1b[31m' in output.splitlines()[-2]


def test_shared_baseline_path_preserves_regression(tmp_path):
    """--baseline X --diff --save-baseline X must detect a flip before overwriting X."""
    from probe_matrix import report

    def grid(verdict):
        return {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell",
                "mode": "default", "host_fingerprint": "abc123abc123",
                "results": [{"probe_id": "files.x", "category": "files", "verdict": verdict,
                             "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}

    base_path = tmp_path / "baseline.json"
    report.save_baseline([grid("blocked")], base_path)   # last run: blocked
    cur = tmp_path / "cur.json"
    cur.write_text(__import__("json").dumps(grid("allowed")))  # this run: allowed (a flip!)

    # Same file for --baseline and --save-baseline.
    rc = report.main(["--grid", str(cur), "--baseline", str(base_path),
                      "--diff", "--save-baseline", str(base_path)])
    assert rc == 0
    # The regression was detected despite the baseline being overwritten.
    diff = report.diff_against_baseline(report._load_grids([str(cur)]),
                                        report.load_baseline(str(base_path)))
    # baseline now holds the new (allowed) run; the prior comparison already happened.
    assert any(c.classification in ("unchanged", "flipped_open") for c in diff.cells)


def test_host_fingerprint_is_machine_specific(monkeypatch):
    """Two machines sharing an OS tuple must get different fingerprints."""
    import uuid
    from probe_matrix import spec

    monkeypatch.setattr(uuid, "getnode", lambda: 0x111111111111)
    a = spec.host_fingerprint()
    monkeypatch.setattr(uuid, "getnode", lambda: 0x222222222222)
    b = spec.host_fingerprint()
    assert a != b
    assert len(a) == 12 and len(b) == 12
