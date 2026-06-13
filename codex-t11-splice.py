#!/usr/bin/env python3
"""codex-t11-splice.py — idempotent splicer for the tournament-11 Codex parity patch.

Applies the X7 / F1 / F3 hardening to a Codex pre_tool_use_dispatch.py *in place*
by string-substitution onto the CURRENT file (not a frozen snapshot), so it stays
correct even as the live hook drifts (e.g. F2/F9 added out-of-band). Every step is
guarded by a presence check, so re-running is a no-op.

Closes, relative to the un-patched live hook:
  - X7  : apply_patch / Edit / redirect writes to the shared ~/.claude control surface
  - F1  : interpreter one-liner writes to ~/.claude AND ~/.codex/data/hooks (kill-switch)
  - F3  : git push to refs/heads/main (no-op if the live hook already covers it)

PII: the control-surface regex matches the literal-path attack form with the
username-agnostic class /Users/[^/\\s]+/ — never a hard-coded username — so this
file is safe to publish. The ~/ and $HOME arms cover the other two spellings.

Usage:
    python3 codex-t11-splice.py <path-to-pre_tool_use_dispatch.py>

Exit 0 on success (applied or already-applied); 3 if an expected anchor is missing
(the live hook diverged in a way this splicer does not understand — do NOT install).
"""

import pathlib
import sys

# ── The 4-arm shared-Claude control-surface regex (username-agnostic) ─────────
# Written as a raw triple-quoted string so backslashes reach the output verbatim.
NEW_RE = r"""
# -- X7 + F1 port: shared Claude control surface (codex-t11-1 + codex-t11-2) --
# Covers redirect/copy writes, bare path matches (apply_patch/Edit), .claude.json,
# and interpreter one-liner writes (python3/node/ruby/perl/swift/osascript/deno/bun).
# Path arm uses /Users/[^/\s]+/ (any user) so no username is hard-coded.
CLAUDE_CONTROL_SURFACE_RE = re.compile(
    # arm 1: redirect/copy operator targeting .claude control paths
    r"(?:>>?|\b(?:tee|cp|mv|install|ln|dd)\b|\bsed\b[^\n]*\s-i)"
    r"[^\n]*(?:/Users/[^/\s]+/|~/|(?<![A-Za-z0-9])\$HOME/)\.claude/"
    r"(?:hooks/|agents/|mcp-gate-policy\.json|settings[^/\s]*\.json|\.tokens)"
    r"|"
    # arm 2: bare path (apply_patch / Edit tool_text serialization)
    r"(?:/Users/[^/\s]+/|~/|(?<![A-Za-z0-9])\$HOME/)"
    r"\.claude/"
    r"(?:hooks/|agents/|mcp-gate-policy\.json|settings[^/\s]*\.json|\.tokens)"
    r"|"
    # arm 3: .claude.json
    r"(?:/Users/[^/\s]+/|~/|(?<![A-Za-z0-9])\$HOME/)\.claude\.json\b"
    r"|"
    # arm 4 (F1 port): interpreter one-liner write to .claude control surface
    r"\b(?:python3?|node|ruby|perl|swift|osascript|deno|bun)\b"
    r"[^\n]*(?:open|write|writeFile(?:Sync)?|File\.write|do shell script)"
    r"[^\n]*(?:/Users/[^/\s]+/|~/|(?<![A-Za-z0-9])\$HOME/)\.claude/",
    re.IGNORECASE,
)
"""

# anchor: end of the CODEX_SELF_WRITE_RE block — insert NEW_RE right after it
ANCHOR = "CODEX_SELF_WRITE_RE = re.compile(\n"
CLOSE = "\n)\n"

# analyze_command guard (Bash path)
OLD_CMD = """    if CODEX_SELF_WRITE_RE.search(command):
        return (
            "deny",
            "Refusing a Bash write to the Codex control surface (~/.codex/hooks, config.toml, "
            "hooks.json, agents). Edit via the editor, not shell redirection/copy.",
        )"""
NEW_CMD = (
    OLD_CMD
    + """

    if CLAUDE_CONTROL_SURFACE_RE.search(command):
        return (
            "deny",
            "Refusing a Bash write to the shared Claude control surface "
            "(~/.claude/hooks, agents, mcp-gate-policy.json, settings, .tokens, .claude.json). "
            "Edit via the editor out-of-band, not from inside a turn.",
        )"""
)

# analyze_non_bash_tool guard (apply_patch / Edit / Write / MCP tool_text)
OLD_NONBASH = """    if read_only_intent and tool_name in {"apply_patch", "Edit", "Write"}:
        action = "approving file edits" if approval_request else "editing files"
        return (
            "deny",
            f"This turn is marked read-only/report-only. Ask the user to change scope before {action}.",
        )"""
NEW_NONBASH = (
    OLD_NONBASH
    + """

    if CLAUDE_CONTROL_SURFACE_RE.search(tool_text):
        target = "Approval request" if approval_request else "Tool input"
        return (
            "deny",
            f"{target} targets the shared Claude control surface "
            "(hooks, agents, mcp-gate-policy.json, settings, .tokens, .claude.json). "
            "Apply control-surface edits out-of-band, not from inside a turn.",
        )"""
)

# CODEX_SELF_WRITE_RE: extend redirect/copy arm with data/hooks/
OLD_CODEX_PATH = r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json)\b"
NEW_CODEX_PATH = (
    r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json|data/hooks/)\b"
)

# CODEX_SELF_WRITE_RE: add an interpreter-write arm (catches the data/hooks kill-switch
# written via python3 -c "open(...)"); must run AFTER the data/hooks extension above.
# Anchor = the single-arm path line *with its trailing comma* (`...)\b",`); the comma
# is what makes this match the real file — dropping it silently no-ops the splice.
_CODEX_ARM = (
    r'r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json|data/hooks/)\b"'
)
OLD_CODEX_CLOSE = _CODEX_ARM + ","
NEW_CODEX_CLOSE = "\n".join(
    [
        _CODEX_ARM,
        r'    r"|"',
        r'    r"\b(?:python3?|node|ruby|perl|swift|osascript|deno|bun)\b"',
        r'    r"[^\n]*(?:open|write|writeFile(?:Sync)?|File\.write)\b"',
        r'    r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json|data/hooks/)",',
    ]
)

# F3: widen push-to-main regexes to the refs/heads/ fully-qualified form
OLD_PUSH = r'r"\bgit\s+push\b[^\n]*(?::(?:main|master)\b|\s(?:main|master)\s*$)"'
NEW_PUSH = (
    r'r"\bgit\s+push\b[^\n]*"'
    + "\n        "
    + r'r"(?::(?:refs/heads/)?(?:main|master)\b|\s(?:refs/heads/)?(?:main|master)\s*$)"'
)
OLD_FORCE = r'r"\bgit\s+push\b[^\n]*\s\+\S+:(?:main|master)\b"'
NEW_FORCE = r'r"\bgit\s+push\b[^\n]*\s\+\S+:(?:refs/heads/)?(?:main|master)\b"'


def splice(src):
    """Return (new_src, applied_steps, errors). Idempotent."""
    applied, errors = [], []

    # 1. Insert CLAUDE_CONTROL_SURFACE_RE + both guard call sites (X7 + F1-claude).
    if "CLAUDE_CONTROL_SURFACE_RE" in src:
        applied.append("control-surface regex: already present (skip)")
    else:
        try:
            idx = src.index(ANCHOR)
            close_idx = src.index(CLOSE, idx) + len(CLOSE)
        except ValueError:
            errors.append("anchor CODEX_SELF_WRITE_RE block not found")
            return src, applied, errors
        src = src[:close_idx] + NEW_RE + src[close_idx:]
        applied.append("control-surface regex: inserted")

        if OLD_CMD in src:
            src = src.replace(OLD_CMD, NEW_CMD, 1)
            applied.append("analyze_command guard: injected")
        else:
            errors.append("analyze_command guard anchor not found")
        if OLD_NONBASH in src:
            src = src.replace(OLD_NONBASH, NEW_NONBASH, 1)
            applied.append("analyze_non_bash_tool guard: injected")
        else:
            errors.append("analyze_non_bash_tool guard anchor not found")

    # 2. Extend CODEX_SELF_WRITE_RE redirect arm with data/hooks/ (F1 codex kill-switch).
    if "data/hooks/" in src and NEW_CODEX_PATH in src:
        applied.append("codex data/hooks path: already present (skip)")
    elif OLD_CODEX_PATH in src:
        src = src.replace(OLD_CODEX_PATH, NEW_CODEX_PATH)
        applied.append("codex data/hooks path: extended")
    # (if neither, a divergent codex regex — not fatal; control-surface still applies)

    # 3. Add interpreter-write arm to CODEX_SELF_WRITE_RE (must follow step 2).
    if OLD_CODEX_CLOSE in src:
        src = src.replace(OLD_CODEX_CLOSE, NEW_CODEX_CLOSE, 1)
        applied.append("codex interpreter arm: added")
    else:
        applied.append("codex interpreter arm: already present or n/a (skip)")

    # 4. F3 push-to-main refs/heads widening (no-op if the live hook already has it).
    if OLD_PUSH in src:
        src = src.replace(OLD_PUSH, NEW_PUSH)
        applied.append("push main pattern: widened to refs/heads/")
    else:
        applied.append("push main pattern: already refs/heads-aware or n/a (skip)")
    if OLD_FORCE in src:
        src = src.replace(OLD_FORCE, NEW_FORCE)
        applied.append("force-push main pattern: widened to refs/heads/")

    return src, applied, errors


def main():
    if len(sys.argv) != 2:
        print("usage: codex-t11-splice.py <path-to-pre_tool_use_dispatch.py>")
        return 2
    path = pathlib.Path(sys.argv[1])
    src = path.read_text()
    new_src, applied, errors = splice(src)
    for step in applied:
        print("  - " + step)
    if errors:
        for e in errors:
            print("  ! ERROR: " + e)
        print("ABORT: live hook diverged from expected anchors — not writing.")
        return 3
    if new_src != src:
        path.write_text(new_src)
        print("Splice written: %s" % path)
    else:
        print("No changes needed (already fully patched): %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
