#!/usr/bin/env python3
from __future__ import annotations

import re
import time
import json

from common import (
    append_audit,
    command_disables_hooks,
    command_has_broken_codex_home_path,
    command_is_personal_ops_recovery_repair,
    command_is_mutating,
    command_is_personal_ops_sensitive_mutation,
    egress_shell_decision,
    egress_tool_decision,
    hooks_disabled,
    load_payload,
    load_turn_state,
    live_personal_ops_recovery_repair_ready,
    write_json,
    SECRET_PATTERNS,
)


DENY_PATTERNS = [
    (
        r"\bgit\s+reset\s+--hard\b",
        "Destructive git history rewrite blocked by hook.",
    ),
    (
        r"\bgit\s+push\b[^\n]*\s(--force|-f)\b",
        "Force push blocked by hook.",
    ),
    (
        r"\bgit\b[^\n]*\s--no-verify\b",
        "Bypassing git verification with --no-verify is blocked by hook.",
    ),
    (
        r"\bgit\s+push\b[^\n]*\s--delete\b",
        "Remote branch deletion is blocked by hook.",
    ),
    (
        r"\bgit\s+checkout\s+--\b",
        "Destructive checkout of tracked files blocked by hook.",
    ),
    (
        r"\bgit\s+clean\s+-[^\n]*\b(x|d|f){2,}",
        "Broad git clean command blocked by hook.",
    ),
    (
        r"\brm\s+-rf\s+(/|~|/Users/operator\b|/Users/operator/\.(codex|ssh|aws|gnupg)\b|\.{1,2}\b)",
        "Broad destructive delete blocked by hook.",
    ),
    (
        r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b",
        "Pipe-to-shell command blocked by hook.",
    ),
    (
        r"\b(eval|bash|sh|zsh|python3?|ruby|perl)\b\s+[<\(]*\s*[$(]*\s*(curl|wget)\b",
        "Downloaded remote execution blocked by hook.",
    ),
    (
        r"\bssh\b[^\n]*\b(rm\s+-rf|curl\b[^\n|]*\|\s*(sh|bash|zsh)|shutdown|reboot)\b",
        "Risky remote shell command blocked by hook.",
    ),
    # F2: Widened DB client list and added non-ANSI destructive verb patterns.
    (
        r"\b(psql|mysql|sqlite3|pgcli|mycli|clickhouse-client|clickhouse|mongosh|mongo|redis-cli|cqlsh|duckdb|surreal)\b[^\n]*(drop\s+(database|schema|table|keyspace|namespace)|truncate\s+table)\b|"
        r"\b(prisma\s+migrate\s+reset|supabase\s+db\s+reset)\b",
        "Destructive database operation blocked by hook.",
    ),
    # F2: Mongo destructive verbs
    (
        r"\b(db\.[A-Za-z0-9_]+\.drop|dropDatabase|db\.dropDatabase)\s*\(",
        "Destructive MongoDB operation blocked by hook.",
    ),
    # F2: Redis destructive verbs
    (
        r"\b(FLUSHALL|FLUSHDB)\b",
        "Destructive Redis operation blocked by hook.",
    ),
    # F2: SurrealDB destructive verbs
    (
        r"\bREMOVE\s+(TABLE|DATABASE|NAMESPACE|INDEX)\b",
        "Destructive SurrealDB operation blocked by hook.",
    ),
    # F3: git push to main/master (including refs/heads/ fully-qualified form)
    (
        r"\bgit\s+push\b[^\n]*(?::(?:refs/heads/)?(?:main|master)\b|\s(?:refs/heads/)?(?:main|master)\s*$)",
        "Push targeting main/master is blocked by hook. Open a PR instead.",
    ),
    # F3: force push (+refspec) to main/master (including refs/heads/ form)
    (
        r"\bgit\s+push\b[^\n]*\s\+\S+:(?:refs/heads/)?(?:main|master)\b",
        "Force push (+refspec) to main/master is blocked by hook.",
    ),
    (
        r"\bDELETE\s+FROM\b(?:(?!\bWHERE\b)[\s\S])*$",
        "DELETE without WHERE is blocked by hook.",
    ),
    (
        r"\bUPDATE\b(?:(?!\bWHERE\b)[\s\S])*\bSET\b(?:(?!\bWHERE\b)[\s\S])*$",
        "UPDATE without WHERE is blocked by hook.",
    ),
    (
        r"\b(psql|mysql|sqlite3|pgcli|mycli|clickhouse-client|clickhouse|mongosh|mongo|redis-cli|cqlsh|duckdb|surreal)\b[^\n]*\s(-f|--file)\s+\S+",
        "Executing a SQL script file (contents not inspectable) is blocked; run manually after review.",
    ),
    (
        r"\b(mkfs(\.\w+)?|diskutil\s+erase\w*|wipefs|shred)\b[^\n]*/dev/",
        "Disk format/erase command blocked by hook.",
    ),
    (
        r"\bdd\b[^\n]*\bof=/dev/",
        "dd writing to a block device is blocked by hook.",
    ),
    (
        r"\bkill\s+-9\s+-1\b",
        "kill -9 -1 (all user processes) blocked by hook.",
    ),
]

# F9: interpreter + destructive FS API + home/system anchor — deny inline
# interpreter calls that target sensitive paths. Relative targets (no anchor)
# are NOT matched and must still pass.
_INTERPRETER_RE = re.compile(
    r"\b(python3?|node|deno|bun|ruby|perl|php)\b",
    re.IGNORECASE,
)
_DESTRUCTIVE_FS_API_RE = re.compile(
    r"(shutil\.rmtree|os\.removedirs|os\.rmdir|os\.remove|os\.unlink|"
    r"\.unlink\(|fs\.rmSync|fs\.rmdirSync|fs\.unlinkSync|fs\.rm\b|"
    r"rmSync|removeSync|File::Path|rmtree|remove_dir_all)",
    re.IGNORECASE,
)
_SENSITIVE_ANCHOR_RE = re.compile(
    r"(~/|\$HOME|/Users/operator/|/usr/|/etc/|/var/|/bin/|/sbin/|/lib/|/System/|/Library/|/private/)",
    re.IGNORECASE,
)


def interpreter_destructive_delete(command: str) -> bool:
    """Return True (deny) when a command runs an interpreter with a destructive FS API
    call AND a home/system path anchor. Relative targets (no anchor) must still ALLOW."""
    return bool(
        _INTERPRETER_RE.search(command)
        and _DESTRUCTIVE_FS_API_RE.search(command)
        and _SENSITIVE_ANCHOR_RE.search(command)
    )


def _load_sensitive_home_segments() -> str:
    """Regex alternation of home-anchored credential segments from the shared policy
    (~/.claude/mcp-gate-policy.json, same file the egress guard reads). Falls back to a
    built-in superset if unreadable — fail-safe, never fail-open."""
    import os
    from pathlib import Path

    fallback = [
        r"\.ssh",
        r"\.aws",
        r"\.gnupg",
        r"\.config/op",
        r"\.config/gcloud",
        r"\.docker/config\.json",
        r"\.kube",
        r"\.netrc",
        r"\.pypirc",
        r"\.npmrc",
        r"\.git-credentials",
        r"\.gem/credentials",
        r"\.anthropic",
        r"\.claude/\.tokens",
        r"\.codex/auth\.json",
        r"\.codex/\.credentials\.json",
    ]
    try:
        policy = Path(
            os.environ.get(
                "CODEX_EGRESS_POLICY",
                str(Path.home() / ".claude" / "mcp-gate-policy.json"),
            )
        )
        segs = (
            json.loads(policy.read_text(encoding="utf-8")).get("sensitive_paths") or {}
        ).get("home")
        if segs:
            return "|".join(re.escape(s) for s in segs)
    except Exception:
        pass
    return "|".join(fallback)


SENSITIVE_PATH_RE = re.compile(
    r"(?:/Users/operator/|~/|\$HOME/)(?:" + _load_sensitive_home_segments() + r")"
    r"|\bid_(?:rsa|ed25519|ecdsa)\b",
    re.IGNORECASE,
)
CLAUDE_MEMORY_PATH_RE = re.compile(
    r"(/Users/operator/|~/)\.claude/projects/[^/]+/memory/[^/\s]+",
    re.IGNORECASE,
)
SENSITIVE_VERB_RE = re.compile(
    r"\b(cat|bat|less|more|view|head|tail|nl|tac|hexdump|xxd|od|strings|"
    r"sed|awk|grep|egrep|fgrep|rg|ag|python|python3|perl|ruby|node|"
    r"cp|mv|tee|install|ln|dd|tar|zip|gzip|gunzip|zcat|base64|base32|"
    r"paste|tr|cut|rev|fold|pbcopy|open|curl|scp|rsync)\b",
    re.IGNORECASE,
)
# Mirror of common.py:731 (disabled.json) extended to the rest of the control surface.
# F1(a): added `touch` to the verb alternation.
# F1(b): interpreter write-to-.codex check is in analyze_command (see below).
CODEX_SELF_WRITE_RE = re.compile(
    r"(?:>>?|\b(?:tee|cp|mv|install|ln|dd|touch)\b|\bsed\b[^\n]*\s-i)"
    r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json|data/hooks/)\b"
    r"|"
    r"\b(?:python3?|node|ruby|perl|swift|osascript|deno|bun)\b"
    r"[^\n]*(?:open|write|writeFile(?:Sync)?|File\.write)\b"
    r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json|data/hooks/)",
    re.IGNORECASE,
)

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

# F1(b): deny an interpreter whose inline command also references .codex control
# surfaces AND contains a write indicator. Plain READs (no write indicator) must ALLOW.
_INTERPRETER_CODEX_WRITE_RE = re.compile(
    r"\b(python3?|node|deno|bun|ruby|perl|php)\b"
    r"(?=(?:(?!\.codex/).)*"  # lookahead: somewhere after the interpreter...
    r"\.codex/(?:hooks/|agents/|config\.toml|hooks\.json))",
    re.IGNORECASE,
)
_CODEX_WRITE_INDICATOR_RE = re.compile(
    r"""['"]\s*[waxWAX]b?\s*['"]|writeFileSync|\.write\s*\(|truncate|>>?""",
    re.IGNORECASE,
)
_CODEX_SURFACE_PATH_RE = re.compile(
    r"\.codex/(?:hooks\b|agents\b|config\.toml\b|hooks\.json\b)",
    re.IGNORECASE,
)

WARN_PATTERNS = [
    (
        r"\bgh\s+pr\s+(create|edit|comment|merge)\b",
        "GitHub PR mutation detected. Confirm the target and remote side effects are intended.",
    ),
    (
        r"\b(npm|pnpm|yarn|bun)\s+(install|add|remove|uninstall)\b",
        "Dependency mutation detected. Confirm the target workspace and lockfile impact.",
    ),
    (
        r"\bbrew\s+(install|uninstall)\b",
        "Machine-wide package mutation detected. Confirm the package and rollback path.",
    ),
    (
        r"\bgit\s+(rebase|merge|cherry-pick|rm)\b",
        "Local git history or tracked-file mutation detected. Confirm the scope is intentional.",
    ),
    (
        r"\bgit\s+worktree\s+(remove|prune)\b",
        "Worktree cleanup detected. Confirm the target worktree is safe to remove.",
    ),
    (
        r"\bcodex\s+cloud\s+(exec|apply)\b",
        "Codex cloud mutation detected. Keep cloud delegation manual-only and confirm device and environment readiness first.",
    ),
    (
        r"\b(chmod|chown)\s+-R\b",
        "Recursive permission change detected. Keep the target narrow.",
    ),
    (
        r"\bfind\b[^\n]*\b-delete\b",
        "find -delete detected. Confirm the search scope is tightly bounded.",
    ),
    (
        r"\b(defaults\s+write|launchctl)\b",
        "System-level command detected. Confirm the target and rollback path.",
    ),
]

MCP_PERSONAL_OPS_MUTATION_RE = re.compile(
    r"(^|[^A-Za-z0-9])(backup|prune|snapshot|restore|repair|maintenance|delete|archive|"
    r"send|write|mutate|apply)([^A-Za-z0-9]|$)",
    re.IGNORECASE,
)
MCP_PERSONAL_OPS_READ_RE = re.compile(
    r"(^|[^A-Za-z0-9])(health|status|list|get|read|search|show|check|audit|"
    r"dry[-_ ]?run)([^A-Za-z0-9]|$)",
    re.IGNORECASE,
)


def analyze_command(
    command: str,
    *,
    read_only_intent: bool = False,
    personal_ops_ready: bool = False,
    personal_ops_recovery_repair_ready: bool = False,
) -> tuple[str, str | None]:
    if command_has_broken_codex_home_path(command):
        return (
            "deny",
            "$CODEX_HOME appears empty or an operating path resolved to /. Use /Users/operator/.codex explicitly before touching automation or hook state.",
        )

    if CODEX_SELF_WRITE_RE.search(command):
        return (
            "deny",
            "Refusing a Bash write to the Codex control surface (~/.codex/hooks, config.toml, "
            "hooks.json, agents). Edit via the editor, not shell redirection/copy.",
        )

    if CLAUDE_CONTROL_SURFACE_RE.search(command):
        return (
            "deny",
            "Refusing a Bash write to the shared Claude control surface "
            "(~/.claude/hooks, agents, mcp-gate-policy.json, settings, .tokens, .claude.json). "
            "Edit via the editor out-of-band, not from inside a turn.",
        )

    # F1(b): deny an interpreter writing to .codex control surfaces inline.
    if (
        _INTERPRETER_RE.search(command)
        and _CODEX_SURFACE_PATH_RE.search(command)
        and _CODEX_WRITE_INDICATOR_RE.search(command)
    ):
        return (
            "deny",
            "Refusing an interpreter write to the Codex control surface (~/.codex/hooks, "
            "config.toml, hooks.json, agents). Edit via the editor, not inline interpreter code.",
        )

    if read_only_intent and command_is_mutating(command):
        return (
            "deny",
            "This turn is marked read-only/report-only. Ask the user to change scope before running mutating commands.",
        )

    if command_is_personal_ops_sensitive_mutation(command) and not personal_ops_ready:
        if (
            personal_ops_recovery_repair_ready
            and command_is_personal_ops_recovery_repair(command)
        ):
            return "allow", None
        if (
            command_is_personal_ops_recovery_repair(command)
            and live_personal_ops_recovery_repair_ready()
        ):
            return "allow", None
        return (
            "deny",
            "Personal-ops mutation requires a fresh ready health check first.",
        )

    if re.search(r"\bgit\s+branch\s+-D\b", command):
        return "deny", "Force branch deletion is blocked by hook."

    for pattern, reason in DENY_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "deny", reason

    # F9: interpreter + destructive FS API + home/system anchor
    if interpreter_destructive_delete(command):
        return (
            "deny",
            "Interpreter-driven destructive filesystem delete targeting a home or system path is blocked by hook.",
        )

    if re.search(r"\bsudo\b", command, re.IGNORECASE):
        return (
            "deny",
            "sudo is blocked by policy. Use an approved machine-level path instead of escalating in-session.",
        )

    if CLAUDE_MEMORY_PATH_RE.search(command) and SENSITIVE_VERB_RE.search(command):
        return (
            "deny",
            "Claude-managed memory file targeted. Use bridge-db or the canonical sync path instead of editing direct memory files.",
        )

    if SENSITIVE_PATH_RE.search(command) and SENSITIVE_VERB_RE.search(command):
        return (
            "deny",
            "Command targets home-level credential material. Read or export it manually if you truly need it.",
        )

    if command_disables_hooks(command):
        return (
            "deny",
            "Disabling the Codex hook layer (CODEX_HOOKS_DISABLE / disabled.json) is "
            "blocked by policy. Toggle hooks out-of-band, not from inside a turn.",
        )

    for _secret in SECRET_PATTERNS:
        if re.search(_secret, command):
            return (
                "deny",
                "Command contains a secret-like literal (API key/token). Pass secrets via an "
                "environment variable or keyring reference, never on the command line.",
            )

    egress = egress_shell_decision(command)
    if egress.decision == "deny":
        return "deny", f"Blocked (egress): {egress.reason}"

    for pattern, reason in WARN_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "warn", reason

    return "allow", None


def payload_text_for_non_bash(tool_input: object) -> str:
    try:
        return json.dumps(tool_input, sort_keys=True)
    except Exception:
        return str(tool_input)


def analyze_non_bash_tool(
    tool_name: str,
    tool_input: object,
    *,
    read_only_intent: bool = False,
    personal_ops_ready: bool = False,
    approval_request: bool = False,
) -> tuple[str, str | None]:
    tool_text = payload_text_for_non_bash(tool_input)
    tool_identity = f"{tool_name} {tool_text}"

    if read_only_intent and tool_name in {"apply_patch", "Edit", "Write"}:
        action = "approving file edits" if approval_request else "editing files"
        return (
            "deny",
            f"This turn is marked read-only/report-only. Ask the user to change scope before {action}.",
        )

    if CLAUDE_CONTROL_SURFACE_RE.search(tool_text):
        target = "Approval request" if approval_request else "Tool input"
        return (
            "deny",
            f"{target} targets the shared Claude control surface "
            "(hooks, agents, mcp-gate-policy.json, settings, .tokens, .claude.json). "
            "Apply control-surface edits out-of-band, not from inside a turn.",
        )

    if CLAUDE_MEMORY_PATH_RE.search(tool_text) or SENSITIVE_PATH_RE.search(tool_text):
        target = "Approval request" if approval_request else "Tool input"
        return (
            "deny",
            f"{target} targets protected credential or Claude-managed memory material.",
        )

    if tool_name.startswith("mcp__personal_ops__"):
        if MCP_PERSONAL_OPS_MUTATION_RE.search(tool_identity):
            if not personal_ops_ready:
                return (
                    "deny",
                    "Personal-ops MCP mutation requires a fresh ready health check first.",
                )
        elif MCP_PERSONAL_OPS_READ_RE.search(tool_identity):
            return "allow", None

    egress = egress_tool_decision(tool_name, tool_input)
    if egress.decision == "deny":
        return "deny", f"Blocked (egress): {egress.reason}"

    return "allow", None


def main() -> int:
    started = time.time()
    if hooks_disabled("PreToolUse"):
        return 0
    payload = load_payload()
    cwd = payload.get("cwd")
    session_id = payload.get("session_id")
    turn_id = payload.get("turn_id")
    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    command = (
        tool_input.get("command") or tool_input.get("cmd")
        if isinstance(tool_input, dict)
        else None
    ) or ""
    state = load_turn_state(session_id, turn_id)
    decision, message = analyze_command(
        command,
        read_only_intent=bool(state.get("read_only_intent")),
        personal_ops_ready=bool(state.get("personal_ops_ready")),
        personal_ops_recovery_repair_ready=bool(
            state.get("personal_ops_recovery_repair_ready")
        ),
    )

    if decision == "allow" and not command:
        decision, message = analyze_non_bash_tool(
            tool_name,
            tool_input,
            read_only_intent=bool(state.get("read_only_intent")),
            personal_ops_ready=bool(state.get("personal_ops_ready")),
        )

    if decision == "deny":
        write_json(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": message,
                }
            }
        )
        append_audit(
            event="PreToolUse",
            decision="deny",
            cwd=cwd,
            tags=["shell_guardrail"],
            result="blocked",
            duration_ms=int((time.time() - started) * 1000),
        )
        return 0

    if decision == "warn" and message:
        write_json({"systemMessage": message})
        append_audit(
            event="PreToolUse",
            decision="warn",
            cwd=cwd,
            tags=["shell_guardrail"],
            duration_ms=int((time.time() - started) * 1000),
        )
        return 0

    append_audit(
        event="PreToolUse",
        decision="allow",
        cwd=cwd,
        tags=["shell_guardrail"],
        duration_ms=int((time.time() - started) * 1000),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
