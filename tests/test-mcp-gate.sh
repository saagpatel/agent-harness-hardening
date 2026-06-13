#!/bin/bash
# test-mcp-gate.sh — RED→GREEN protocol for tournament-11 findings C3, C4, C5.
#
# For each finding:
#   RED   — LIVE guard on attack payload  → expected: ALLOW  (demonstrates the gap)
#   GREEN — STAGED patched guard on same  → expected: DENY or REQUIRE-TOKEN
#   REG   — STAGED guard on benign call   → expected: ALLOW  (regression check)
#
# Usage:
#   bash tests/test-mcp-gate.sh
# from the staging/tournament-11/ directory, or pass a custom guard path:
#   MCP_GATE_POLICY=./mcp-gate-policy.json bash tests/test-mcp-gate.sh
#
# For require_token findings (C3, C5): "GREEN = require-token" means the patched
# guard returns a deny with "requires operator confirmation" message when no token
# exists in the token dir.  The test creates a tempdir as the token dir to ensure
# no ambient tokens interfere.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LIVE_GUARD="$HOME/.claude/hooks/mcp-guard.sh"
STAGED_GUARD="$STAGING_DIR/mcp-guard.sh"
STAGED_POLICY="$STAGING_DIR/mcp-gate-policy.json"
LIVE_POLICY="$HOME/.claude/mcp-gate-policy.json"

# Temp token dir — empty so no ambient tokens interfere.
TMPTOKEN=$(mktemp -d)
trap 'rm -rf "$TMPTOKEN"' EXIT

# ── helpers ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
TOTAL=0

run_guard() {
  # Usage: run_guard <guard> <fixture> [policy]
  # policy defaults to STAGED_POLICY; pass LIVE_POLICY for RED tests on the live guard.
  local guard="$1" fixture="$2" policy="${3:-$STAGED_POLICY}"
  MCP_GATE_POLICY="$policy" \
  CLAUDE_TOKEN_DIR="$TMPTOKEN" \
  bash "$guard" < "$fixture" 2>/dev/null
}

# check_with_policy: like check() but accepts an explicit policy path.
check_with_policy() {
  local label="$1" guard="$2" fixture="$3" expected="$4" policy="$5"
  TOTAL=$((TOTAL+1))
  local out
  out=$(run_guard "$guard" "$fixture" "$policy")
  local got
  got=$(classify "$out")
  if [ "$got" = "$expected" ]; then
    echo "  PASS  $label  [got: $got]"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $label  [expected: $expected, got: $got]"
    echo "        output: $(echo "$out" | jq -rc '.hookSpecificOutput.permissionDecisionReason // "allow"' 2>/dev/null | head -c 120)"
    FAIL=$((FAIL+1))
  fi
}

# outcome: "allow" | "deny" | "require-token"
classify() {
  local output="$1"
  if echo "$output" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
    local reason
    reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')
    if echo "$reason" | grep -qi "requires operator confirmation\|require.*token\|high-risk"; then
      echo "require-token"
    else
      echo "deny"
    fi
  else
    echo "allow"
  fi
}

check() {
  local label="$1" guard="$2" fixture="$3" expected="$4"
  TOTAL=$((TOTAL+1))
  local out
  out=$(run_guard "$guard" "$fixture")
  local got
  got=$(classify "$out")
  if [ "$got" = "$expected" ]; then
    echo "  PASS  $label  [got: $got]"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $label  [expected: $expected, got: $got]"
    echo "        output: $(echo "$out" | jq -rc '.hookSpecificOutput.permissionDecisionReason // "allow"' 2>/dev/null | head -c 120)"
    FAIL=$((FAIL+1))
  fi
}

# ── Validate staged policy JSON ───────────────────────────────────────────────
echo "=== Policy JSON validation ==="
if jq empty "$STAGED_POLICY" 2>/dev/null; then
  echo "  PASS  staged mcp-gate-policy.json parses cleanly"
  PASS=$((PASS+1))
else
  echo "  FAIL  staged mcp-gate-policy.json is invalid JSON"
  FAIL=$((FAIL+1))
fi
TOTAL=$((TOTAL+1))

# Confirm C3 entries present in require_token.
for entry in \
    'mcp__*ctx_execute*' \
    'mcp__*ctx_execute_file*' \
    'mcp__serena__replace_symbol_body' \
    'mcp__serena__rename_symbol' \
    'mcp__serena__safe_delete_symbol' \
    'mcp__engraph__delete' \
    'mcp__engraph__rewrite' \
    'mcp__engraph__move_note'; do
  TOTAL=$((TOTAL+1))
  if jq -e --arg e "$entry" '.require_token | map(select(. == $e)) | length > 0' "$STAGED_POLICY" >/dev/null 2>&1; then
    echo "  PASS  policy contains require_token entry: $entry"
    PASS=$((PASS+1))
  else
    echo "  FAIL  policy MISSING require_token entry: $entry"
    FAIL=$((FAIL+1))
  fi
done
echo ""

# ── C3: ungated code-exec ─────────────────────────────────────────────────────
echo "=== C3: ungated arbitrary code-exec (ctx_execute) ==="
echo "  --- ctx_execute ---"
check_with_policy "C3-RED   ctx_execute no-token (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C3-ctx-execute-benign.json" "allow" "$LIVE_POLICY"
check "C3-GREEN ctx_execute no-token (STAGED guard)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C3-ctx-execute-benign.json" "require-token"
# Regression: benign engraph__search (not in require_token) should still allow.
cat > "$TMPTOKEN/benign-engraph.json" <<'EOF'
{"tool_name":"mcp__engraph__search","tool_input":{"query":"tauri nspanel"}}
EOF
check "C3-REG   engraph__search benign (STAGED guard)" \
  "$STAGED_GUARD" "$TMPTOKEN/benign-engraph.json" "allow"

echo ""
echo "  --- serena__replace_symbol_body ---"
check_with_policy "C3-RED   serena__replace_symbol_body no-token (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C3-serena-replace-attack.json" "allow" "$LIVE_POLICY"
check "C3-GREEN serena__replace_symbol_body no-token (STAGED guard)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C3-serena-replace-attack.json" "require-token"
# Regression: serena__find_symbol (not destructive) should allow.
cat > "$TMPTOKEN/benign-serena.json" <<'EOF'
{"tool_name":"mcp__serena__find_symbol","tool_input":{"name_path_pattern":"Button"}}
EOF
check "C3-REG   serena__find_symbol benign (STAGED guard)" \
  "$STAGED_GUARD" "$TMPTOKEN/benign-serena.json" "allow"

echo ""
echo "  --- engraph__delete ---"
check_with_policy "C3-RED   engraph__delete no-token (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C-engraph-delete-allow.json" "allow" "$LIVE_POLICY"
check "C3-GREEN engraph__delete no-token (STAGED guard)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C-engraph-delete-allow.json" "require-token"
echo ""

# ── C4: control-plane write sentinel ─────────────────────────────────────────
echo "=== C4: MCP write-channel to control plane ==="
echo "  --- serena writing mcp-guard.sh (hook) ---"
# RED: live guard + live policy. serena__replace_symbol_body is NOT in live require_token
# so the live guard allows it. (The live guard has it in non_egress_servers as a
# non-egress local tool, so no egress gate either.)
check_with_policy "C4-RED   serena write .claude/hooks/mcp-guard.sh (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C4-serena-hook-write.json" "allow" "$LIVE_POLICY"
check "C4-GREEN serena write .claude/hooks/mcp-guard.sh (STAGED guard — C4 deny)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C4-serena-hook-write.json" "deny"

echo ""
echo "  --- engraph writing .claude/settings.json ---"
check_with_policy "C4-RED   engraph write .claude/settings.json (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C4-engraph-settings-write.json" "allow" "$LIVE_POLICY"
check "C4-GREEN engraph write .claude/settings.json (STAGED guard — C4 deny)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C4-engraph-settings-write.json" "deny"

echo ""
echo "  --- serena writing SKILL.md (skill injection, .claude/ relative path) ---"
# r1-E-serena-skill-write.json uses a bare relative path 'skills/evil/SKILL.md'
# without the .claude/ prefix — misses C4 sentinel but hits C3 token gate.
# r1-C4-serena-skill-inject-abs.json uses '.claude/skills/evil/SKILL.md' which
# is the real attack vector (serena cwd = project root = $HOME or ~).
check_with_policy "C4-RED   serena write .claude/skills/evil/SKILL.md (LIVE guard+policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C4-serena-skill-inject-abs.json" "allow" "$LIVE_POLICY"
check "C4-GREEN serena write .claude/skills/evil/SKILL.md (STAGED C4 deny)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C4-serena-skill-inject-abs.json" "deny"
# Original fixture (bare relative path) — C3 token gate fires instead of C4 sentinel.
check "C4-NOTE  r1-E-serena-skill-write bare-path → require-token (C3, not C4)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-E-serena-skill-write.json" "require-token"

echo ""
echo "  --- Regression: serena writing normal src file ---"
# C4 sentinel must NOT block writes to normal project source files.
# r1-C4-benign-serena-src.json targets src/components/Button.tsx — no control-plane path.
# However serena__replace_symbol_body IS in require_token (C3), so STAGED will
# require-token (not deny-sentinel). RED (LIVE) allows it; STAGED requires token.
# Both are correct: C4 sentinel doesn't fire on normal source paths.
check_with_policy "C4-REG   serena write src/components/Button.tsx — LIVE allows (no token in live policy)" \
  "$LIVE_GUARD" "$SCRIPT_DIR/r1-C4-benign-serena-src.json" "allow" "$LIVE_POLICY"
check "C4-REG   serena write src/components/Button.tsx — STAGED requires token (C3, not C4 deny)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r1-C4-benign-serena-src.json" "require-token"

echo ""
echo "  --- Regression: serena__find_symbol (read-only) ---"
check_with_policy "C4-REG   serena__find_symbol — LIVE allows" \
  "$LIVE_GUARD" "$TMPTOKEN/benign-serena.json" "allow" "$LIVE_POLICY"
check "C4-REG   serena__find_symbol — STAGED allows" \
  "$STAGED_GUARD" "$TMPTOKEN/benign-serena.json" "allow"
echo ""

# ── C5: token not bound to tool — scoped token preferred ─────────────────────
echo "=== C5: tool-scoped token validation ==="
# Scenario: a scoped token for 'ctx_execute' exists; an attempt to use a
# 'serena_write'-class token for ctx_execute should NOT find it.
# Scenario: a bare (legacy) token is accepted for any class.

echo "  --- bare (legacy) token authorizes ctx_execute ---"
BARE_TOKEN="deadbeef0011"
echo "issued" > "$TMPTOKEN/$BARE_TOKEN"
# Use a fresh mtime — touch to now.
touch "$TMPTOKEN/$BARE_TOKEN"
# We can't test the live guard's token logic against the staged guard's token dir
# easily here (live guard uses its own token dir default). Use STAGED guard + env.
out=$(MCP_GATE_POLICY="$STAGED_POLICY" CLAUDE_TOKEN_DIR="$TMPTOKEN" \
      bash "$STAGED_GUARD" < "$SCRIPT_DIR/r1-C3-ctx-execute-benign.json" 2>/dev/null)
got=$(classify "$out")
TOTAL=$((TOTAL+1))
if [ "$got" = "allow" ]; then
  echo "  PASS  C5: bare token '$BARE_TOKEN' authorizes ctx_execute (backward compat) [got: allow]"
  PASS=$((PASS+1))
else
  echo "  FAIL  C5: bare token should authorize ctx_execute [expected: allow, got: $got]"
  FAIL=$((FAIL+1))
fi

echo "  --- scoped token ctx_execute authorizes ctx_execute ---"
SCOPED_TOKEN="cafebabe1234"
echo "issued" > "$TMPTOKEN/${SCOPED_TOKEN}.ctx_execute"
touch "$TMPTOKEN/${SCOPED_TOKEN}.ctx_execute"
out=$(MCP_GATE_POLICY="$STAGED_POLICY" CLAUDE_TOKEN_DIR="$TMPTOKEN" \
      bash "$STAGED_GUARD" < "$SCRIPT_DIR/r1-C3-ctx-execute-benign.json" 2>/dev/null)
got=$(classify "$out")
TOTAL=$((TOTAL+1))
if [ "$got" = "allow" ]; then
  echo "  PASS  C5: scoped token '*.ctx_execute' authorizes ctx_execute [got: allow]"
  PASS=$((PASS+1))
else
  echo "  FAIL  C5: scoped token '*.ctx_execute' should authorize ctx_execute [expected: allow, got: $got]"
  FAIL=$((FAIL+1))
fi

echo "  --- scoped token for wrong class does NOT authorize serena_write ---"
# Token dir now has: .ctx_execute scoped token (just issued). No serena_write or bare token.
# Remove any bare token first.
rm -f "$TMPTOKEN/$BARE_TOKEN"
out=$(MCP_GATE_POLICY="$STAGED_POLICY" CLAUDE_TOKEN_DIR="$TMPTOKEN" \
      bash "$STAGED_GUARD" < "$SCRIPT_DIR/r1-C3-serena-replace-attack.json" 2>/dev/null)
got=$(classify "$out")
TOTAL=$((TOTAL+1))
if [ "$got" = "require-token" ]; then
  echo "  PASS  C5: wrong-class scoped token (ctx_execute) rejected for serena_write [got: require-token]"
  PASS=$((PASS+1))
else
  echo "  FAIL  C5: wrong-class scoped token should be rejected for serena_write [expected: require-token, got: $got]"
  FAIL=$((FAIL+1))
fi

echo "  --- scoped token serena_write authorizes serena__replace_symbol_body ---"
SERENA_TOKEN="aabbccdd9900"
echo "issued" > "$TMPTOKEN/${SERENA_TOKEN}.serena_write"
touch "$TMPTOKEN/${SERENA_TOKEN}.serena_write"
out=$(MCP_GATE_POLICY="$STAGED_POLICY" CLAUDE_TOKEN_DIR="$TMPTOKEN" \
      bash "$STAGED_GUARD" < "$SCRIPT_DIR/r1-C3-serena-replace-attack.json" 2>/dev/null)
got=$(classify "$out")
TOTAL=$((TOTAL+1))
if [ "$got" = "allow" ]; then
  echo "  PASS  C5: scoped token '*.serena_write' authorizes serena__replace_symbol_body [got: allow]"
  PASS=$((PASS+1))
else
  echo "  FAIL  C5: scoped token '*.serena_write' should authorize serena__replace_symbol_body [expected: allow, got: $got]"
  FAIL=$((FAIL+1))
fi
echo ""

# ── Existing r5-R fixtures (regression for prior fixes) ──────────────────────
# Note: r5-R fixtures are metadata-only records (no tool_name field). The guard
# exits early (allow) when no tool_name is present — these confirm that inert
# fixture files don't cause false denies.
echo "=== Prior findings regression (r5-R inert metadata fixtures) ==="
check "r5-R mcp-resources-unguarded inert fixture (no tool_name → allow)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r5-R-mcp-resources-unguarded.json" "allow"
check "r5-R tokens-read-gap inert fixture (no tool_name → allow)" \
  "$STAGED_GUARD" "$SCRIPT_DIR/r5-R-tokens-read-gap.json" "allow"
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "=== Results: $PASS passed, $FAIL failed, $TOTAL total ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
