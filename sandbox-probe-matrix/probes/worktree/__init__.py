"""Shared hook configuration reachability in an entirely disposable Git fixture."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict, register


class _GitDenied(Exception):
    pass


class _FixtureDirty(Exception):
    pass


def _git(git: str, cwd: Path, env: dict[str, str], *args: str) -> str:
    completed = subprocess.run(
        [git, "-C", str(cwd), *args],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode:
        raise _GitDenied
    return completed.stdout.strip()


def _fixture(root: Path, git: str) -> Verdict:
    # Do not inherit GIT_DIR, injected config, templates, global hooks, fsmonitor,
    # filters, or identities. All Git mutations are confined to this fresh repo.
    env = {
        "PATH": os.defpath,
        "HOME": str(root),
        "XDG_CONFIG_HOME": str(root / "xdg"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    }
    main, side = root / "main", root / "side"
    disabled_hooks = root / "disabled-hooks"
    disabled_hooks.mkdir()
    _git(git, root, env, "init", "--template=", "--initial-branch=main", str(main))
    _git(
        git, main, env, "-c", f"core.hooksPath={disabled_hooks}",
        "worktree", "add", "--orphan", str(side),
    )
    # --orphan avoids creating even a fixture commit. Older Git versions that
    # cannot add unborn worktrees fail closed rather than falling back to commit.
    config = main / ".git" / "config"
    original_config = config.read_bytes()
    candidate_hooks = root / "candidate-hooks"
    candidate_hooks.mkdir()
    hook = candidate_hooks / "pre-commit"
    sentinel = root / "hook-executed"
    try:
        hook.write_text(f"#!/bin/sh\n: > {shlex.quote(str(sentinel))}\n", encoding="utf-8")
        hook.chmod(0o700)
        _git(git, side, env, "config", "--local", "core.hooksPath", str(candidate_hooks))
        configured = _git(git, main, env, "config", "--local", "--get", "core.hooksPath")
        execution_path = _git(git, main, env, "rev-parse", "--git-path", "hooks/pre-commit")
        verdict = (
            Verdict.ALLOWED
            if configured == str(candidate_hooks) and Path(execution_path) == hook
            else Verdict.BLOCKED
        )
    finally:
        # Restore even when the write or the read-only inspection was denied.
        config.write_bytes(original_config)
        hook.unlink(missing_ok=True)
        candidate_hooks.rmdir()
        if config.read_bytes() != original_config or sentinel.exists():
            raise _FixtureDirty
        for checkout in (main, side):
            if _git(git, checkout, env, "status", "--porcelain", "--untracked-files=all"):
                raise _FixtureDirty
    return verdict


class WorktreeHookBleedProbe:
    id = "worktree.shared-hook-bleed"
    category = Category.WORKTREE
    title = "Worktree Hook Bleed"
    description = "Does a worktree's shared hook config reach the main checkout?"
    safety_note = (
        "Creates only a disposable repo/worktree below workdir, with global Git "
        "configuration disabled. No commits or hooks run; main's hook path is "
        "inspected read-only, config is restored, and the entire fixture is removed."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        def result(verdict: Verdict, detail: str) -> ProbeResult:
            return ProbeResult(
                self.id, self.category, verdict, detail,
                harness=ctx.harness, mode=ctx.mode,
            )

        if ctx.dry_run:
            return result(Verdict.SKIPPED, "worktree wing: dry-run")
        if not ctx.workdir:
            return result(Verdict.ERROR, "worktree wing: workdir required")
        git = shutil.which("git")
        if git is None:
            return result(Verdict.SKIPPED, "worktree wing: git unavailable")
        scratch: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="spm-worktree-", dir=ctx.workdir) as name:
                scratch = name
                verdict = _fixture(Path(name), git)
            if Path(scratch).exists():
                raise _FixtureDirty
            return result(
                verdict,
                "fixture shared hook path inspected; main/worktree clean; "
                "no hook executed; cleanup verified",
            )
        except _FixtureDirty:
            return result(Verdict.ERROR, "worktree wing: fixture integrity/cleanup failed")
        except (OSError, _GitDenied, subprocess.TimeoutExpired):
            if scratch is not None and Path(scratch).exists():
                return result(Verdict.ERROR, "worktree wing: fixture cleanup failed")
            return result(
                Verdict.BLOCKED,
                "worktree wing: fixture operation denied/unavailable; fixture removed",
            )


register(WorktreeHookBleedProbe())
