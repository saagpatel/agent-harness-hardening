from pathlib import Path

import pytest

from probe_matrix.spec import ProbeContext, Verdict, all_probes
import probes.temp as temp_wing


def test_registered():
    probe = temp_wing.SharedTempLeakProbe()
    assert any(item.id == probe.id for item in all_probes())


def test_dry_run_is_skipped(tmp_path: Path) -> None:
    probe = temp_wing.SharedTempLeakProbe()
    assert probe.run(ProbeContext(dry_run=True)).verdict == Verdict.SKIPPED


def test_no_handoff_is_skipped_unsupported(tmp_path: Path) -> None:
    # Without a real writer-session handoff the cross-session boundary is not
    # exercised: SKIPPED (unsupported), never a false ALLOWED leak.
    result = temp_wing.SharedTempLeakProbe().run(
        ProbeContext(workdir=str(tmp_path), harness="test", mode="isolated")
    )
    assert result.verdict == Verdict.SKIPPED
    assert "unsupported in-process" in result.detail
    assert result.harness == "test" and result.mode == "isolated"


def test_reader_reaches_writer_marker_is_allowed(tmp_path: Path) -> None:
    # An independent writer session (here, the test) left a marker; the reader
    # session shares the same root and reaches it -> ALLOWED. The probe writes
    # nothing: the only file present is the one the test created.
    reader_root = tmp_path / "reader"
    reader_root.mkdir()
    sentinel = bytes.fromhex("00ff11ee22dd")
    marker = reader_root / "writer-marker"
    marker.write_bytes(sentinel)
    before = set(reader_root.iterdir())

    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(extra={
        "writer_marker": str(marker),
        "writer_sentinel": sentinel.hex(),
        "reader_root": str(reader_root),
    }))
    assert result.verdict == Verdict.ALLOWED
    assert "reader read the writer's marker" in result.detail
    # The probe created/deleted nothing.
    assert set(reader_root.iterdir()) == before


def test_reader_cannot_reach_isolated_marker_is_blocked(tmp_path: Path, monkeypatch) -> None:
    # Isolated sessions: the reader's root cannot reach the writer's marker.
    reader_root = tmp_path / "reader"
    reader_root.mkdir()
    sentinel = bytes.fromhex("abababababab")
    marker = tmp_path / "writer" / "marker"

    import errno as _errno

    def deny(_path):  # a read DENIED by permission -> boundary held
        raise PermissionError(_errno.EACCES, "denied")

    monkeypatch.setattr(Path, "read_bytes", lambda self: deny(self))
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(extra={
        "writer_marker": str(marker),
        "writer_sentinel": sentinel.hex(),
        "reader_root": str(reader_root),
    }))
    assert result.verdict == Verdict.BLOCKED


def test_wrong_sentinel_is_inconclusive_not_a_leak_or_hold(tmp_path: Path) -> None:
    # A read that returns something other than the writer's sentinel means the
    # handoff is unverified: inconclusive (ERROR), neither a leak nor a hold.
    reader_root = tmp_path / "reader"
    reader_root.mkdir()
    marker = reader_root / "writer-marker"
    marker.write_bytes(b"something-else")
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(extra={
        "writer_marker": str(marker),
        "writer_sentinel": "00ff11ee22dd",  # does not match the marker contents
        "reader_root": str(reader_root),
    }))
    assert result.verdict == Verdict.ERROR
    assert "mismatch" in result.detail


def test_bad_sentinel_hex_is_error(tmp_path: Path) -> None:
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(extra={
        "writer_marker": str(tmp_path / "m"),
        "writer_sentinel": "nothex",
        "reader_root": str(tmp_path),
    }))
    assert result.verdict == Verdict.ERROR


def test_missing_marker_is_inconclusive(tmp_path: Path) -> None:
    # A deleted/absent writer marker is inconclusive (ERROR), not a false hold.
    reader_root = tmp_path / "reader"
    reader_root.mkdir()
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(extra={
        "writer_marker": str(reader_root / "nope"),
        "writer_sentinel": "00ff11ee22dd",
        "reader_root": str(reader_root),
    }))
    assert result.verdict == Verdict.ERROR
