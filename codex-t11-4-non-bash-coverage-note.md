# codex-t11-4-non-bash-coverage-note.md

**Finding ID:** apply_patch coverage note  
**Severity:** DOCUMENTATION / guard completeness  
**CC counterpart:** CC `pre_tool_use.py` applies the same SENSITIVE/MEMORY checks to both bash and non-bash paths  
**File:** `~/.codex/hooks/pre_tool_use_dispatch.py`

## What this note documents

`analyze_non_bash_tool` (lines 322–361) currently runs two path checks:

```python
if CLAUDE_MEMORY_PATH_RE.search(tool_text) or SENSITIVE_PATH_RE.search(tool_text):
    ...deny...
```

`CLAUDE_MEMORY_PATH_RE` matches `~/.claude/projects/*/memory/*` files.
`SENSITIVE_PATH_RE` matches home-anchored credential paths loaded from `mcp-gate-policy.json`
`sensitive_paths.home` — which includes `.claude/.tokens`, `.ssh`, `.aws`, etc.

### What it misses

`SENSITIVE_PATH_RE` does **NOT** cover:

| Path | Why not covered |
|---|---|
| `~/.claude/hooks/` | Not in `sensitive_paths.home` |
| `~/.claude/agents/` | Not in `sensitive_paths.home` |
| `~/.claude/mcp-gate-policy.json` | Not in `sensitive_paths.home` |
| `~/.claude/settings*.json` | Not in `sensitive_paths.home` |
| `~/.claude.json` | Not in `sensitive_paths.home` |

An `apply_patch` tool call that modifies any of these paths passes through `analyze_non_bash_tool`
unblocked, as confirmed by:

```
$ python3 ~/.codex/hooks/pre_tool_use_dispatch.py \
    < ~/Projects/fable-outputs/staging/tournament-11/tests/r1-D-x7-applypatch.json 2>&1
(empty — EXIT:0 / ALLOW)
```

The test event patches `~/.claude/mcp-gate-policy.json` to flip `"default":"allow"`.

### The fix (already covered by codex-t11-1)

Patch T11-1 adds `CLAUDE_CONTROL_SURFACE_RE` and inserts a check in `analyze_non_bash_tool`
**before** the existing `CLAUDE_MEMORY_PATH_RE | SENSITIVE_PATH_RE` check:

```python
# (inserted by codex-t11-1, ~line 339 post-patch)
if CLAUDE_CONTROL_SURFACE_RE.search(tool_text):
    target = "Approval request" if approval_request else "Tool input"
    return (
        "deny",
        f"{target} targets the shared Claude control surface "
        "(hooks, agents, mcp-gate-policy.json, settings, .tokens, .claude.json). "
        "Apply control-surface edits out-of-band, not from inside a turn.",
    )
```

This closes the gap for `apply_patch`, `Edit`, and any other non-Bash tool whose `tool_input`
serializes to a string containing one of the control-surface paths.

### Why SENSITIVE_PATH_RE alone is insufficient

`sensitive_paths.home` is operator-maintained and designed for credential paths. It is
deliberately narrow. Bolting control-surface paths onto it would conflate two different
concerns — credential exfiltration (read-oriented) and harness tampering (write-oriented) —
and would create confusion about which paths are "credentials" vs "control surface."
The `CLAUDE_CONTROL_SURFACE_RE` added by T11-1 is the right separation.

### Check completeness after T11-1 + T11-2

After both patches are applied, `analyze_non_bash_tool` will check, in order:

1. `read_only_intent` guard (existing)
2. `CLAUDE_CONTROL_SURFACE_RE` — write to hooks/agents/settings/policy/tokens (NEW, T11-1)
3. `CLAUDE_MEMORY_PATH_RE | SENSITIVE_PATH_RE` — memory files + credentials (existing)
4. `mcp__personal_ops__` mutation gate (existing)
5. Egress guard (existing)

No additional change needed to `analyze_non_bash_tool` beyond what T11-1 provides.

## Residual limits (all four patches)

The following attack surfaces remain outside scope of this patch set:

1. **PostToolUse coverage gap.** `post_tool_use_dispatch.py` runs after Bash for Codex surface
   change detection but does NOT re-check the `.claude` control surface. A write that somehow
   bypasses PreToolUse (e.g., via a Codex tool not matched by the `Bash` matcher) would land
   undetected. Mitigation: hooks.json matcher `apply_patch|mcp__.*` already covers non-Bash.
   A future hardening pass should add `.claude` path detection to `post_tool_use_dispatch.py`
   as belt-and-suspenders.

2. **Unicode / homoglyph bypass.** The regexes use literal ASCII path components. A command
   with Unicode lookalike characters in the path (e.g., homoglyph `/`) could evade. Mitigation:
   Codex normalizes paths before tool dispatch; this is low-probability for a well-behaved agent
   but remains a theoretical bypass. Defense-in-depth would add a `unicodedata.normalize('NFC')`
   pass over the command string before regex checks — not in scope for this patch set.

3. **Symlink traversal.** A command that writes to a symlink pointing INTO `.claude/hooks/` is
   not caught by path matching on the symlink's name. The existing T11-1 control-surface check
   only inspects the literal string in the command. Full mitigation requires filesystem-level
   resolution (not feasible in a synchronous hook). Accept risk; flag in operator runbook.

4. **`data/hooks/disabled.json` via non-Bash tools.** T11-2 adds the interpreter pattern for
   Bash. If a future MCP tool can write arbitrary files (e.g., a filesystem MCP), the
   `analyze_non_bash_tool` path only checks the serialized `tool_text` for the control-surface
   RE. This is correct as written — but operators should audit new MCP server additions for
   arbitrary write capability.

5. **CC-side `protect-claude-writes.sh` is a separate enforcement layer.** These Codex-side
   patches bring Codex to PARITY; they do not replace the CC-side protection. Both layers
   should remain in force.

## APPLY note

This file is documentation only — no code changes needed beyond T11-1 and T11-2.
Review the residual limits paragraph and decide whether PostToolUse coverage (item 1) warrants
a T11-5 patch in a follow-up round.
