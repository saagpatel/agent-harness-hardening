# R3-K: Subagent Hook Scope — Evidence Dossier

## Primary question
Do PreToolUse hooks (Bash/mcp__.*) fire for a subagent's own tool calls,
or only for the lead's tool calls?

## Evidence chain

### 1. settings.json hook matchers
```
PreToolUse:
  matcher: "Bash"   → block-dangerous-cmds.sh, db-guard.sh, remote-command-guard.sh,
                       git-safety.sh, defer-destructive.sh, protect-sensitive-reads.sh,
                       confirm-token-required.sh, lockfile-freeze.sh,
                       bash-secret-guard.sh, bash-egress-guard.sh, protect-claude-writes.sh
  matcher: "Agent"  → haiku-routing-classifier.sh, subagent-scope-linter.sh
  matcher: "mcp__.*"→ mcp-guard.sh
SubagentStop:
  (no matcher)      → subagent-quality-gate.sh [command], + [agent type] Sonnet reviewer
```

### 2. CC hook architecture (from recon-report.md + harness memory)
- Hooks are registered in ~/.claude/settings.json and fire in the SESSION context.
- `CLAUDE_CODE_SUBAGENT_MODEL` hard-pins ALL spawned subagents to Sonnet —
  this is a platform-level env var, confirming subagents run in their own
  CC session context, not the lead's context.
- CC changelog v2.1.172: "Sub-agents can now spawn their own sub-agents
  (up to 5 levels deep)" — confirms subagents are independent sessions.
- The `SubagentStop` event fires in the PARENT session when a subagent stops.
  This is a distinct event from PreToolUse — meaning the parent monitors
  subagent lifecycle but tool calls happen in the subagent's own session.

### 3. The architecture implies
Per CC's documented hook model, hooks in settings.json fire for the session
where the settings.json is loaded. Since all sessions on this machine share
~/.claude/settings.json (user-scope settings), hooks DO fire for subagent
tool calls within the same user context. This is different from cross-machine
or multi-tenant scenarios.

HOWEVER: the haiku-routing-classifier.sh fires on matcher "Agent" — meaning
it fires when the LEAD calls the Agent tool. When a SUBAGENT (already running)
calls a further Agent tool (nested sub-subagent, supported since v2.1.172),
that inner Agent dispatch would also pass through the haiku-routing-classifier
because it matches "Agent" in the subagent's own session context.

### 4. The specific gap: agent-type SubagentStop hook is itself a subagent
The SubagentStop `type: "agent"` hook spawns a Sonnet reviewer.
That reviewer is itself a subagent dispatched by the CC runtime.
Its tool calls (if any) go through the normal hook stack — guarded.
Its INPUT is the stopped subagent's final message, passed via the CC runtime
(not shell string interpolation) — safe.

### 5. Conclusion on privilege laundering
VERDICT: Guards DO fire for subagent tool calls (shared ~/.claude/settings.json).
A lead cannot privilege-launder by delegating a blocked Bash/MCP call to a
subagent — the same hooks fire in the subagent's session.

EXCEPTION SURFACE: The haiku-routing-classifier blocks on "Agent" tool dispatches
matching PRO_RE. A subagent that itself dispatches a further Agent tool (nested
sub-subagent, v2.1.172 feature) passes through the classifier in the inner session.
The classifier checks `subagent_type` but has a SPECIALIST EXEMPTION list — if a
novel specialist type is added that is exempt from classification, it bypasses
model enforcement.

## Reproduction evidence
See r3-K-haiku-classifier-bypass.json and r3-K-nested-agent-escape.json for
inert payload demonstrations.
