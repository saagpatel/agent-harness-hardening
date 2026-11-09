from pathlib import Path

import pytest

from probe_matrix.spec import ProbeContext, Verdict, all_probes
import probes.temp as temp_wing


def test_registered_and_modeled_roots_cleaned(tmp_path: Path) -> None:
    probe = temp_wing.SharedTempLeakProbe()
    assert any(item.id == probe.id for item in all_probes())
    result = probe.run(ProbeContext(workdir=str(tmp_path), harness="test", mode="isolated"))
    assert result.verdict == Verdict.ALLOWED
    assert result.harness == "test" and result.mode == "isolated"
    assert "current identity" in result.detail
    assert "cleanup verified" in result.detail
    assert list(tmp_path.iterdir()) == []


def test_same_root_positive_control_preserves_existing_files(tmp_path: Path) -> None:
    workdir, session = tmp_path / "scratch", tmp_path / "session"
    workdir.mkdir()
    session.mkdir()
    existing = session / "existing"
    existing.write_bytes(b"unrelated fixture data")
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(
        workdir=str(workdir),
        extra={"session_a_tmp": str(session), "session_b_tmp": str(session)},
    ))
    assert result.verdict == Verdict.ALLOWED
    assert "supplied roots: allowed" in result.detail
    assert list(workdir.iterdir()) == []
    assert list(session.iterdir()) == [existing]
    assert existing.read_bytes() == b"unrelated fixture data"


def test_real_roots_cleaned_after_denied_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workdir, writer, reader = (tmp_path / name for name in ("scratch", "a", "b"))
    for directory in (workdir, writer, reader):
        directory.mkdir()
    original = temp_wing._read_marker

    def deny_supplied(reader_root: Path, marker: Path) -> bytes:
        if reader_root == reader:
            raise PermissionError("sensitive diagnostic must not escape")
        return original(reader_root, marker)

    monkeypatch.setattr(temp_wing, "_read_marker", deny_supplied)
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(
        workdir=str(workdir),
        extra={"session_a_tmp": str(writer), "session_b_tmp": str(reader)},
    ))
    assert result.verdict == Verdict.BLOCKED
    assert "sensitive diagnostic" not in result.detail
    assert "cleanup verified" in result.detail
    assert all(list(directory.iterdir()) == [] for directory in (workdir, writer, reader))


def test_denied_marker_creation_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny(*args: object, **kwargs: object) -> None:
        raise PermissionError

    monkeypatch.setattr(temp_wing.tempfile, "mkstemp", deny)
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(workdir=str(tmp_path)))
    assert result.verdict == Verdict.BLOCKED
    assert list(tmp_path.iterdir()) == []


def test_cleanup_failure_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    unlink = Path.unlink

    def deny_marker_unlink(path: Path, missing_ok: bool = False) -> None:
        if path.name.startswith("spm-marker-"):
            raise PermissionError
        unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", deny_marker_unlink)
    result = temp_wing.SharedTempLeakProbe().run(ProbeContext(workdir=str(tmp_path)))
    assert result.verdict == Verdict.ERROR
    assert "cleanup failed" in result.detail
    # TemporaryDirectory's independent cleanup still removed the model marker.
    assert list(tmp_path.iterdir()) == []


def test_dry_run_and_incomplete_roots_do_not_write(tmp_path: Path) -> None:
    probe = temp_wing.SharedTempLeakProbe()
    assert probe.run(ProbeContext(workdir=str(tmp_path), dry_run=True)).verdict == Verdict.SKIPPED
    result = probe.run(ProbeContext(workdir=str(tmp_path), extra={"session_a_tmp": "unused"}))
    assert result.verdict == Verdict.ERROR
    assert list(tmp_path.iterdir()) == []
