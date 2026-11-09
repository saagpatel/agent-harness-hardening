import os
from pathlib import Path

import pytest

from probe_matrix.spec import ProbeContext, Verdict, all_probes
import probes.worktree as worktree_wing


def test_main_would_use_hook_but_never_executes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_run = worktree_wing._run_git
    calls: list[tuple[str, ...]] = []
    inspected_hooks: list[Path] = []
    clean_checkouts: list[Path] = []

    def inspect(git: str, cwd: Path, env: dict[str, str], *args: str) -> tuple[int, str]:
        calls.append(args)
        # Inherited configuration cannot redirect the fixture to a real repo.
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull
        assert "GIT_DIR" not in env and "GIT_CONFIG_COUNT" not in env
        rc, output = original_run(git, cwd, env, *args)
        if args == ("rev-parse", "--git-path", "hooks/pre-commit"):
            hook = Path(output)
            inspected_hooks.append(hook)
            assert hook.is_file() and os.access(hook, os.X_OK)
            assert "hook-executed" in hook.read_text()
            assert not (cwd.parent / "hook-executed").exists()
        if args == ("status", "--porcelain", "--untracked-files=all"):
            clean_checkouts.append(cwd)
            assert output == ""
            assert not (cwd.parent / "hook-executed").exists()
            assert not (cwd.parent / "candidate-hooks").exists()
            assert b"hooksPath" not in (cwd.parent / "main" / ".git" / "config").read_bytes()
        return rc, output

    monkeypatch.setenv("GIT_DIR", str(tmp_path / "must-not-use"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "must-not-use-hooks"))
    monkeypatch.setattr(worktree_wing, "_run_git", inspect)
    probe = worktree_wing.WorktreeHookBleedProbe()
    assert any(item.id == probe.id for item in all_probes())
    result = probe.run(ProbeContext(workdir=str(tmp_path), harness="test", mode="fixture"))
    # On a Git that supports --orphan worktrees the write reaches main (ALLOWED);
    # either way it must never be a false BLOCKED and never execute a hook.
    assert result.verdict in (Verdict.ALLOWED, Verdict.SKIPPED)
    assert result.harness == "test" and result.mode == "fixture"
    assert not any("commit" in args or "commit-tree" in args for args in calls)
    assert all(not hook.exists() for hook in inspected_hooks)
    assert list(tmp_path.iterdir()) == []
    if result.verdict == Verdict.ALLOWED:
        assert "cleanup verified" in result.detail
        assert len(inspected_hooks) == 1
        assert {checkout.name for checkout in clean_checkouts} == {"main", "side"}


def test_shared_config_write_denied_is_blocked_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_write = worktree_wing._git_write

    def deny_write(git: str, cwd: Path, env: dict[str, str], *args: str) -> str:
        if args[:3] == ("config", "--local", "core.hooksPath"):
            raise worktree_wing._GitDenied
        return original_write(git, cwd, env, *args)

    monkeypatch.setattr(worktree_wing, "_git_write", deny_write)
    result = worktree_wing.WorktreeHookBleedProbe().run(ProbeContext(workdir=str(tmp_path)))
    # A demonstrated denial of the tested write is the one true BLOCKED.
    assert result.verdict == Verdict.BLOCKED
    assert "denied" in result.detail
    assert list(tmp_path.iterdir()) == []


def test_git_setup_unavailable_is_skipped_not_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fixture setup (init / worktree add --orphan) that a Git build cannot perform
    # must SKIP, never masquerade as a blocked boundary.
    def unavailable(*args: object, **kwargs: object) -> str:
        raise worktree_wing._SetupUnavailable

    monkeypatch.setattr(worktree_wing, "_git_setup", unavailable)
    result = worktree_wing.WorktreeHookBleedProbe().run(ProbeContext(workdir=str(tmp_path)))
    assert result.verdict == Verdict.SKIPPED
    assert "unsupported" in result.detail
    assert list(tmp_path.iterdir()) == []


def test_readback_failure_is_error_not_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(*args: object, **kwargs: object) -> str:
        raise worktree_wing._MeasureFailed

    monkeypatch.setattr(worktree_wing, "_git_read", unreadable)
    result = worktree_wing.WorktreeHookBleedProbe().run(ProbeContext(workdir=str(tmp_path)))
    assert result.verdict == Verdict.ERROR
    assert list(tmp_path.iterdir()) == []


def test_dry_run_and_missing_workdir_never_start_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> tuple[int, str]:
        pytest.fail("git must not run")

    monkeypatch.setattr(worktree_wing, "_run_git", forbidden)
    probe = worktree_wing.WorktreeHookBleedProbe()
    assert probe.run(ProbeContext(workdir=str(tmp_path), dry_run=True)).verdict == Verdict.SKIPPED
    assert probe.run(ProbeContext()).verdict == Verdict.ERROR
    assert list(tmp_path.iterdir()) == []
