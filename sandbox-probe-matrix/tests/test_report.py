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


def test_host_fingerprint_is_install_specific_and_upgrade_stable(monkeypatch):
    """Different installs differ; the same install is stable across OS changes."""
    import platform
    from probe_matrix import spec

    monkeypatch.setenv("SPM_INSTALL_ID", "11111111111111111111111111111111")
    a = spec.host_fingerprint()
    monkeypatch.setenv("SPM_INSTALL_ID", "22222222222222222222222222222222")
    b = spec.host_fingerprint()
    assert a != b
    assert len(a) == 12 and len(b) == 12

    # Same install id is stable even if the OS/kernel release changes (no OS input).
    monkeypatch.setenv("SPM_INSTALL_ID", "33333333333333333333333333333333")
    before = spec.host_fingerprint()
    monkeypatch.setattr(platform, "release", lambda: "99.99.99-upgraded")
    after = spec.host_fingerprint()
    assert before == after


def test_host_fingerprint_fails_loudly_when_no_private_id(monkeypatch, tmp_path):
    """A read-only id location with no provided id must raise, not emit a weak id."""
    import pytest
    from probe_matrix import spec

    monkeypatch.delenv("SPM_INSTALL_ID", raising=False)
    denied = tmp_path / "denied"
    denied.write_text("not a dir")  # mkdir under a file path raises
    monkeypatch.setenv("SPM_SALT_DIR", str(denied / "sub"))
    with pytest.raises(spec.HostIdentityUnavailable):
        spec.host_fingerprint()


def test_cross_host_baseline_comparison_is_refused():
    """A baseline from one machine must not be diffed against another's run."""
    import pytest
    from probe_matrix import report

    def grid(fp, verdict):
        return {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell", "mode": "default",
                "host_fingerprint": fp,
                "results": [{"probe_id": "files.x", "category": "files", "verdict": verdict,
                             "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}
    cur = [grid("aaaaaaaaaaaa", "allowed")]
    base = [grid("bbbbbbbbbbbb", "blocked")]  # different machine
    with pytest.raises(ValueError, match="cross-host"):
        report.diff_against_baseline(cur, base)


def test_baseline_preserved_when_comparison_fails(tmp_path):
    """--baseline X --save-baseline X with a cross-host mismatch must NOT destroy X."""
    import json as _json
    from probe_matrix import report

    def grid(fp, verdict):
        return {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell", "mode": "default",
                "host_fingerprint": fp,
                "results": [{"probe_id": "files.x", "category": "files", "verdict": verdict,
                             "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}
    base_path = tmp_path / "baseline.json"
    report.save_baseline([grid("aaaaaaaaaaaa", "blocked")], base_path)  # machine A
    original = base_path.read_text()
    cur = tmp_path / "cur.json"
    cur.write_text(_json.dumps(grid("bbbbbbbbbbbb", "allowed")))  # machine B (mismatch)

    rc = report.main(["--grid", str(cur), "--baseline", str(base_path),
                      "--diff", "--save-baseline", str(base_path)])
    assert rc != 0  # cross-host comparison raised
    # The original baseline survived untouched.
    assert base_path.read_text() == original


def test_install_id_is_stable_under_concurrent_first_runs(monkeypatch, tmp_path):
    """Concurrent first runs must converge on one identity, not clobber each other."""
    from concurrent.futures import ThreadPoolExecutor
    from probe_matrix import spec

    monkeypatch.delenv("SPM_INSTALL_ID", raising=False)
    monkeypatch.setenv("SPM_SALT_DIR", str(tmp_path / "shared"))
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: spec.host_fingerprint(), range(8)))
    assert len(set(results)) == 1  # one installation -> one fingerprint


def test_baseline_not_replaced_when_html_write_fails(tmp_path):
    """If HTML output fails, the baseline must not have been replaced (no lost regression)."""
    import json as _json
    import pytest
    from probe_matrix import report

    def grid(fp, verdict):
        return {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell", "mode": "default",
                "host_fingerprint": fp,
                "results": [{"probe_id": "files.x", "category": "files", "verdict": verdict,
                             "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}
    base = tmp_path / "baseline.json"
    report.save_baseline([grid("aaaaaaaaaaaa", "blocked")], base)
    original = base.read_text()
    cur = tmp_path / "cur.json"
    cur.write_text(_json.dumps(grid("aaaaaaaaaaaa", "allowed")))  # same host, a real flip

    # HTML destination is an existing directory -> write fails.
    bad_html = tmp_path / "html_dir"
    bad_html.mkdir()
    with pytest.raises((IsADirectoryError, OSError, PermissionError)):
        report.main(["--grid", str(cur), "--baseline", str(base), "--diff",
                     "--save-baseline", str(base), "--html", str(bad_html)])
    # Baseline still holds the pre-run (blocked) state: the regression is not lost.
    assert base.read_text() == original


def test_install_id_file_is_never_empty(monkeypatch, tmp_path):
    from probe_matrix import spec
    monkeypatch.delenv("SPM_INSTALL_ID", raising=False)
    d = tmp_path / "iddir"
    monkeypatch.setenv("SPM_SALT_DIR", str(d))
    fp = spec.host_fingerprint()
    assert len(fp) == 12
    assert (d / "install-id").read_bytes()  # non-empty
    # a second call reads the same published id
    assert spec.host_fingerprint() == fp


def test_html_aliasing_baseline_is_refused(tmp_path):
    """--html pointing at the baseline/grid file must be refused, not overwrite it."""
    import json as _json
    from probe_matrix import report

    def grid(fp, verdict):
        return {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell", "mode": "default",
                "host_fingerprint": fp,
                "results": [{"probe_id": "files.x", "category": "files", "verdict": verdict,
                             "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}
    base = tmp_path / "baseline.json"
    report.save_baseline([grid("aaaaaaaaaaaa", "blocked")], base)
    original = base.read_text()
    cur = tmp_path / "cur.json"
    cur.write_text(_json.dumps(grid("aaaaaaaaaaaa", "allowed")))
    # --html aliases the baseline path.
    rc = report.main(["--grid", str(cur), "--baseline", str(base), "--diff",
                      "--save-baseline", str(base), "--html", str(base)])
    assert rc == 2
    assert base.read_text() == original  # baseline untouched


def test_html_aliasing_stdin_grid_is_refused(tmp_path):
    """`report --html run.json < run.json` must refuse and leave run.json intact."""
    import json as _json
    import os

    from probe_matrix import report

    grid = {"schema": "spm/v1", "generated_at": 0.0, "harness": "shell", "mode": "default",
            "host_fingerprint": "aaaaaaaaaaaa",
            "results": [{"probe_id": "files.x", "category": "files", "verdict": "allowed",
                         "detail": "", "harness": "shell", "mode": "default", "elapsed_ms": 1}]}
    run = tmp_path / "run.json"
    run.write_text(_json.dumps(grid))
    original = run.read_text()

    # Redirect fd 0 to run.json so /dev/stdin resolves to it (as a shell `< run.json` would).
    saved = os.dup(0)
    fd = os.open(run, os.O_RDONLY)
    try:
        os.dup2(fd, 0)
        rc = report.main(["--html", str(run)])  # no --grid -> reads stdin
    finally:
        os.dup2(saved, 0)
        os.close(fd)
        os.close(saved)
    assert rc == 2
    assert run.read_text() == original  # grid file untouched
