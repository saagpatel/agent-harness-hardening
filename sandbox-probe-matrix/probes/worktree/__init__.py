"""Shared hook configuration reachability in an entirely disposable Git fixture.

A BLOCKED verdict is reserved for a *demonstrated denial of the tested write*
(setting `core.hooksPath` from the worktree) or for a measured non-reach. Fixture
setup that a Git build cannot perform (e.g. unborn `--orphan` worktrees on an old
Git) yields SKIPPED, and an inability to read back the result yields ERROR — never
a false BLOCKED that would later masquerade as a blocked->allowed regression.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict, register


class _GitDenied(Exception):
    """The tested write was denied (a demonstrated boundary hold)."""


class _SetupUnavailable(Exception):
    """Fixture setup could not run on this Git build; nothing was measured."""


class _MeasureFailed(Exception):
    """The result could not be read back; nothing was measured."""


class _FixtureDirty(Exception):
    pass


def _run_git(git: str, cwd: Path, env: dict[str, str], *args: str) -> tuple[int, str, str]:
    completed = subprocess.run(
        [git, "-C", str(cwd), *args],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,  # captured PRIVATELY to classify denial vs other; never emitted
        text=True,
        timeout=15,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr


def _is_permission_denial(stderr: str) -> bool:
    s = stderr.lower()
    return ("permission denied" in s
            or "operation not permitted" in s
            or "read-only file system" in s)


def _git_write(git: str, cwd: Path, env: dict[str, str], *args: str) -> str:
    """The tested operation. Only an explicit permission denial is BLOCKED; a lock,
    resource or I/O failure is inconclusive (not a demonstrated denial)."""
    rc, out, err = _run_git(git, cwd, env, *args)
    if rc:
        if _is_permission_denial(err):
            raise _GitDenied
        raise _MeasureFailed  # lock/resource/io: could not measure, not a denial
    return out


def _git_setup(git: str, cwd: Path, env: dict[str, str], *args: str) -> str:
    """Fixture setup. A failure means we could not measure, not that it was blocked."""
    rc, out, _err = _run_git(git, cwd, env, *args)
    if rc:
        raise _SetupUnavailable
    return out


def _git_read(git: str, cwd: Path, env: dict[str, str], *args: str) -> str:
    """Read-back of the result. A failure means we could not measure."""
    rc, out, _err = _run_git(git, cwd, env, *args)
    if rc:
        raise _MeasureFailed
    return out


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
    # --- setup (unavailable -> SKIPPED, never BLOCKED) ---
    _git_setup(git, root, env, "init", "--template=", "--initial-branch=main", str(main))
    _git_setup(
        git, main, env, "-c", f"core.hooksPath={disabled_hooks}",
        "worktree", "add", "--orphan", str(side),
    )
    # --orphan avoids creating even a fixture commit. Older Git versions that
    # cannot add unborn worktrees surface as SKIPPED rather than a false BLOCKED.
    config = main / ".git" / "config"
    original_config = config.read_bytes()
    candidate_hooks = root / "candidate-hooks"
    candidate_hooks.mkdir()
    hook = candidate_hooks / "pre-commit"
    sentinel = root / "hook-executed"
    try:
        hook.write_text(f"#!/bin/sh\n: > {shlex.quote(str(sentinel))}\n", encoding="utf-8")
        hook.chmod(0o700)
        # --- the tested write: can the worktree set main's shared hook path? ---
        _git_write(git, side, env, "config", "--local", "core.hooksPath", str(candidate_hooks))
        # --- read-back: did it reach main's execution path? ---
        configured = _git_read(git, main, env, "config", "--local", "--get", "core.hooksPath")
        execution_path = _git_read(git, main, env, "rev-parse", "--git-path", "hooks/pre-commit")
        verdict = (
            Verdict.ALLOWED
            if configured == str(candidate_hooks) and Path(execution_path) == hook
            else Verdict.BLOCKED
        )
    finally:
        # Restore the config ONLY if it actually changed. When the tested write was
        # denied the config is already intact, and an unconditional restore write
        # would itself hit the same write denial and raise in finally — masking the
        # demonstrated BLOCKED as an ERROR. Restoring only on change avoids that.
        if config.read_bytes() != original_config:
            config.write_bytes(original_config)
        hook.unlink(missing_ok=True)
        candidate_hooks.rmdir()
        if config.read_bytes() != original_config or sentinel.exists():
            raise _FixtureDirty
        for checkout in (main, side):
            _rc, dirty, _err = _run_git(git, checkout, env, "status", "--porcelain", "--untracked-files=all")
            if dirty:
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
        except _SetupUnavailable:
            return result(Verdict.SKIPPED, "worktree wing: git fixture setup unsupported (e.g. --orphan worktrees)")
        except _MeasureFailed:
            return result(Verdict.ERROR, "worktree wing: could not read back shared hook path")
        except _FixtureDirty:
            return result(Verdict.ERROR, "worktree wing: fixture integrity/cleanup failed")
        except _GitDenied:
            return result(
                Verdict.BLOCKED,
                "worktree wing: shared hook-path write denied from the worktree",
            )
        except (OSError, subprocess.TimeoutExpired):
            return result(Verdict.ERROR, "worktree wing: fixture error; measurement incomplete")


register(WorktreeHookBleedProbe())
