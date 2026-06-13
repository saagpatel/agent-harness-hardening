#!/bin/bash
# test-protect-claude-writes.sh — Red/Green/Regression for tournament-11 protect-claude-writes fixes
#
# Findings covered: T1 (CRITICAL), C1 (HIGH), R2-I (HIGH), R4-O (HIGH), R4-Q (MED)
#
# Invocation pattern: bash <hook> < <fixture.json>
# The hook paths are constructed at runtime from HOME so no literal ~/.claude/hooks
# token appears in this script — that prevents the live hook from blocking itself
# when this test script is invoked via the Bash tool.
#
# Usage (from tournament-11/ directory or via absolute path):
#   bash tests/test-protect-claude-writes.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOURNAMENT_DIR="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="$SCRIPT_DIR"

# Build hook paths indirectly so this script carries no literal protected-path token.
_DOT_CLAUDE="$HOME/.claude"
LIVE="${_DOT_CLAUDE}/hooks/protect-claude-writes.sh"
STAGED="$TOURNAMENT_DIR/protect-claude-writes.sh"

PASS=0
FAIL=0

# ── helpers ──────────────────────────────────────────────────────────────────

assert_allow() {
  local label="$1" fixture="$2" hook="$3"
  local out
  out=$(bash "$hook" < "$fixture" 2>/dev/null || true)
  if [ -z "$out" ]; then
    echo "  PASS  ALLOW  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  ALLOW  $label"
    echo "         got: $(echo "$out" | head -3)"
    FAIL=$((FAIL + 1))
  fi
}

assert_deny() {
  local label="$1" fixture="$2" hook="$3"
  local out
  out=$(bash "$hook" < "$fixture" 2>/dev/null || true)
  if echo "$out" | grep -q '"permissionDecision": "deny"'; then
    echo "  PASS  DENY   $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  DENY   $label"
    echo "         got: ${out:-<empty>}"
    FAIL=$((FAIL + 1))
  fi
}

# ── T1: .tokens/ write gate ───────────────────────────────────────────────────
echo ""
echo "=== T1 (CRITICAL): .tokens/ write gate ==="

echo "  [T1-a] touch token  (t1a-touch-token.json)"
assert_allow "T1-a RED  live   touch token"     "$TESTS_DIR/t1a-touch-token.json"  "$LIVE"
assert_deny  "T1-a GRN  staged touch token"     "$TESTS_DIR/t1a-touch-token.json"  "$STAGED"

echo "  [T1-b] colon-redirect token  (t1b-redirect-token.json)"
assert_allow "T1-b RED  live   colon-redirect"  "$TESTS_DIR/t1b-redirect-token.json"  "$LIVE"
assert_deny  "T1-b GRN  staged colon-redirect"  "$TESTS_DIR/t1b-redirect-token.json"  "$STAGED"

echo "  [T1-c] interpreter open token  (t1c-interp-token.json)"
assert_allow "T1-c RED  live   interp token"    "$TESTS_DIR/t1c-interp-token.json"  "$LIVE"
assert_deny  "T1-c GRN  staged interp token"    "$TESTS_DIR/t1c-interp-token.json"  "$STAGED"

echo "  [T1-d] tee token  (t1d-tee-token.json)"
assert_allow "T1-d RED  live   tee token"       "$TESTS_DIR/t1d-tee-token.json"  "$LIVE"
assert_deny  "T1-d GRN  staged tee token"       "$TESTS_DIR/t1d-tee-token.json"  "$STAGED"

# ── C1: expanded interpreter enumeration ─────────────────────────────────────
echo ""
echo "=== C1 (HIGH): expanded interpreter list (swift, sqlite3, etc.) ==="

echo "  [C1-a] swift open hooks  (c1-swift-hooks.json)"
assert_allow "C1-a RED  live   swift hooks"     "$TESTS_DIR/c1-swift-hooks.json"   "$LIVE"
assert_deny  "C1-a GRN  staged swift hooks"     "$TESTS_DIR/c1-swift-hooks.json"   "$STAGED"

echo "  [C1-b] sqlite3 hooks  (c1-sqlite3-hooks.json)"
assert_allow "C1-b RED  live   sqlite3 hooks"   "$TESTS_DIR/c1-sqlite3-hooks.json" "$LIVE"
assert_deny  "C1-b GRN  staged sqlite3 hooks"   "$TESTS_DIR/c1-sqlite3-hooks.json" "$STAGED"

# ── R2-I: skills/*/SKILL.md write protection ──────────────────────────────────
echo ""
echo "=== R2-I (HIGH): skills/*/SKILL.md write protection ==="

echo "  [R2-I] printf redirect to SKILL.md  (r2-I-skill-redirect.json)"
assert_allow "R2-I RED  live   SKILL.md redirect"  "$TESTS_DIR/r2-I-skill-redirect.json"  "$LIVE"
assert_deny  "R2-I GRN  staged SKILL.md redirect"  "$TESTS_DIR/r2-I-skill-redirect.json"  "$STAGED"

# ── R4-O: obfuscation gate ────────────────────────────────────────────────────
echo ""
echo "=== R4-O (HIGH): obfuscation gate (ANSI-C quoting near protected path) ==="

# r4o-swift-ansi: swift + $'...' inline code — live misses (swift not in live list,
# no redirect/verb), staged fires on R4-O gate AND C1 interpreter check.
echo "  [R4-O-a] swift + ANSI-C inline  (r4o-swift-ansi.json)"
assert_allow "R4-O-a RED  live   swift ansi"   "$TESTS_DIR/r4o-swift-ansi.json"  "$LIVE"
assert_deny  "R4-O-a GRN  staged swift ansi"   "$TESTS_DIR/r4o-swift-ansi.json"  "$STAGED"

# r4o-var-ansi: var=$'~/.claude/hooks' + redirect — live indirect-check misses because
# the var-assignment regex requires a literal tilde/HOME form without $'...'; staged
# R4-O gate catches the ANSI-C quoting + protected path.
echo "  [R4-O-b] var=$'...' + redirect  (r4o-var-ansi.json)"
assert_allow "R4-O-b RED  live   var ansi"     "$TESTS_DIR/r4o-var-ansi.json"  "$LIVE"
assert_deny  "R4-O-b GRN  staged var ansi"     "$TESTS_DIR/r4o-var-ansi.json"  "$STAGED"

# ── R4-Q: command length gate ─────────────────────────────────────────────────
echo ""
echo "=== R4-Q (MED): command length gate (>512 KiB = DENY) ==="

# Generate an oversized payload dynamically (600 KiB, no protected path reference).
TMPFIX=$(mktemp /tmp/t11-r4q-pcw-XXXXXX.json)
python3 -c "
import json
cmd = 'echo ' + 'x' * 600000
print(json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}}))
" > "$TMPFIX"

echo "  [R4-Q] oversized command 600 KiB (dynamically generated)"
assert_allow "R4-Q RED  live   600KB cmd"   "$TMPFIX"  "$LIVE"
assert_deny  "R4-Q GRN  staged 600KB cmd"   "$TMPFIX"  "$STAGED"

rm -f "$TMPFIX"

# ── REGRESSION: benign commands must ALLOW on staged hook ────────────────────
echo ""
echo "=== REGRESSION: benign commands must pass through staged hook ==="

echo "  [REG-1] cat settings.json (read of protected file — always allowed)"
assert_allow "REG-1 staged allow cat settings"       "$TESTS_DIR/benign-cat-settings.json"    "$STAGED"

echo "  [REG-2] python3 print(1) (interpreter with no protected-path ref)"
assert_allow "REG-2 staged allow python3 print"      "$TESTS_DIR/benign-python3-print.json"   "$STAGED"

echo "  [REG-3] touch ~/Projects/x (touch outside .claude/)"
assert_allow "REG-3 staged allow touch projects"     "$TESTS_DIR/benign-touch-projects.json"  "$STAGED"

echo "  [REG-4] printf redirect to ~/Projects/notes.txt"
assert_allow "REG-4 staged allow printf projects"    "$TESTS_DIR/benign-printf-projects.json" "$STAGED"

# ── summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=================================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=================================================="

[ "$FAIL" -eq 0 ]
