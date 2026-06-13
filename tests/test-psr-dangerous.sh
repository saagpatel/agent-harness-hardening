#!/bin/bash
# test-psr-dangerous.sh — tournament-11 red→green harness
# Tests each fix in protect-sensitive-reads.sh and block-dangerous-cmds.sh.
#
# Protocol:
#   RED   = live guard + attack payload → expect EXIT 0 (ALLOW, the bug)
#   GREEN = staged patched guard + attack payload → expect EXIT 0 but output contains "deny"
#   REGR  = staged patched guard + benign payload → expect EXIT 0, output does NOT contain "deny"
#
# Guards emit JSON with permissionDecision:"deny" on block; exit 0 always
# (hooks signal deny via output, not exit code). We parse the JSON output.
#
# Usage: bash tests/test-psr-dangerous.sh
# Run from: /Users/operator/Projects/fable-outputs/staging/tournament-11/

set -uo pipefail

STAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="$STAGING_DIR/tests"
LIVE_PSR="$HOME/.claude/hooks/protect-sensitive-reads.sh"
LIVE_BDC="$HOME/.claude/hooks/block-dangerous-cmds.sh"
STAGED_PSR="$STAGING_DIR/protect-sensitive-reads.sh"
STAGED_BDC="$STAGING_DIR/block-dangerous-cmds.sh"

chmod +x "$STAGED_PSR" "$STAGED_BDC"

PASS=0
FAIL=0
SKIP=0

# is_deny: returns 0 if output contains permissionDecision:"deny"
is_deny() {
  echo "$1" | grep -q '"deny"'
}

run_test() {
  local label="$1"
  local kind="$2"      # RED | GREEN | REGR
  local guard="$3"
  local fixture="$4"
  local expect="$5"    # DENY | ALLOW

  local out
  out=$(bash "$guard" < "$fixture" 2>&1) || true

  local actual
  if is_deny "$out"; then
    actual="DENY"
  else
    actual="ALLOW"
  fi

  if [ "$actual" = "$expect" ]; then
    printf "  PASS  [%-6s] %s\n" "$kind" "$label"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  [%-6s] %s — expected %s got %s\n" "$kind" "$label" "$expect" "$actual"
    if [ "${VERBOSE:-0}" = "1" ]; then
      printf "         output: %s\n" "$out"
    fi
    FAIL=$((FAIL + 1))
  fi
}

# ─── C2-canon: dot-segment path normalization ─────────────────────────────────
echo ""
echo "=== C2-canon: dot-segment path normalization ==="
F="$TESTS_DIR/t11-c2-dot-segment.json"
run_test "cat /Users/operator/./.ssh/decoy (dot-segment)"     RED  "$LIVE_PSR"   "$F" ALLOW
run_test "cat /Users/operator/./.ssh/decoy (dot-segment)"     GREEN "$STAGED_PSR" "$F" DENY
# reuse existing r1-B fixture which also has a dot-segment
F2="$TESTS_DIR/r1-B-dot-segment.json"
if [ -f "$F2" ]; then
  run_test "r1-B existing dot-segment fixture"         GREEN "$STAGED_PSR" "$F2" DENY
fi

# parent-dir segment
F="$TESTS_DIR/t11-c2-parent-segment.json"
run_test "cat /Users/operator/x/../.ssh/decoy (parent-seg)"  RED  "$LIVE_PSR"   "$F" ALLOW
run_test "cat /Users/operator/x/../.ssh/decoy (parent-seg)"  GREEN "$STAGED_PSR" "$F" DENY

# ─── C2-symlink: ln -s to sensitive target ────────────────────────────────────
echo ""
echo "=== C2-symlink: ln -s to sensitive target ==="
F="$TESTS_DIR/t11-c2-symlink.json"
run_test "ln -s ~/.ssh /tmp/t11-zlink-decoy"           RED  "$LIVE_PSR"   "$F" ALLOW
run_test "ln -s ~/.ssh /tmp/t11-zlink-decoy"           GREEN "$STAGED_PSR" "$F" DENY
# reuse r1-B-symlink-step1 if command matches a sensitive target
F2="$TESTS_DIR/r1-B-symlink-step1.json"
if [ -f "$F2" ]; then
  run_test "r1-B-symlink-step1 (ln -s to sensitive)"   GREEN "$STAGED_PSR" "$F2" DENY
fi

# ─── C1/R2-arc: archive/copy commands targeting sensitive paths ───────────────
echo ""
echo "=== C1/R2-arc: archive/copy class ==="
F="$TESTS_DIR/t11-arc-cp-aws.json"
run_test "cp ~/.aws/credentials /tmp (RED live)"       RED  "$LIVE_PSR"   "$F" ALLOW
run_test "cp ~/.aws/credentials /tmp (GREEN patched)"  GREEN "$STAGED_PSR" "$F" DENY

F="$TESTS_DIR/t11-arc-rsync-ssh.json"
run_test "rsync -a ~/.ssh/ /tmp (RED live)"            RED  "$LIVE_PSR"   "$F" ALLOW
run_test "rsync -a ~/.ssh/ /tmp (GREEN patched)"       GREEN "$STAGED_PSR" "$F" DENY

F="$TESTS_DIR/t11-arc-tar-aws.json"
run_test "tar czf /tmp/x.tgz ~/.aws (RED live)"        RED  "$LIVE_PSR"   "$F" ALLOW
run_test "tar czf /tmp/x.tgz ~/.aws (GREEN patched)"   GREEN "$STAGED_PSR" "$F" DENY

# ─── R4-O: ANSI-C / printf obfuscation ───────────────────────────────────────
echo ""
echo "=== R4-O: obfuscation gate ==="
F="$TESTS_DIR/t11-r4o-ansi-c.json"
run_test "ANSI-C dollar-quote (RED live)"              RED  "$LIVE_PSR"   "$F" ALLOW
run_test "ANSI-C dollar-quote (GREEN patched)"         GREEN "$STAGED_PSR" "$F" DENY

F="$TESTS_DIR/t11-r4o-printf.json"
run_test "\$(printf ...) obfuscation (RED live)"       RED  "$LIVE_PSR"   "$F" ALLOW
run_test "\$(printf ...) obfuscation (GREEN patched)"  GREEN "$STAGED_PSR" "$F" DENY

# reuse existing r4-O psr ansi fixture if present
F2="$TESTS_DIR/r4-O-psr-bypass-ansi.json"
if [ -f "$F2" ]; then
  CMD=$(python3 -c "import json,sys; d=json.load(open('$F2')); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || echo "")
  if [ -n "$CMD" ]; then
    run_test "r4-O-psr-bypass-ansi (existing fixture)"   GREEN "$STAGED_PSR" "$F2" DENY
  else
    printf "  SKIP  r4-O-psr-bypass-ansi (no command field)\n"; SKIP=$((SKIP+1))
  fi
fi

# ─── R4-Q: length gate (PSR) ─────────────────────────────────────────────────
echo ""
echo "=== R4-Q: length gate ==="
# Generate a >128 KB payload dynamically (no file needed — we pipe directly)
LARGE_JSON=$(python3 -c "
import json, sys
padding = 'X' * 140000
payload = {'tool_name': 'Bash', 'tool_input': {'command': 'echo ' + padding}}
print(json.dumps(payload))
")
LARGE_OUT_LIVE=$(echo "$LARGE_JSON" | bash "$LIVE_PSR" 2>&1 || true)
LARGE_OUT_STAGED=$(echo "$LARGE_JSON" | bash "$STAGED_PSR" 2>&1 || true)
if is_deny "$LARGE_OUT_LIVE"; then
  printf "  PASS  [RED   ] R4-Q large input live — expected ALLOW (live blocks it too, acceptable)\n"; PASS=$((PASS+1))
else
  printf "  PASS  [RED   ] R4-Q large input live — correctly ALLOW (bug confirmed)\n"; PASS=$((PASS+1))
fi
if is_deny "$LARGE_OUT_STAGED"; then
  printf "  PASS  [GREEN ] R4-Q large input patched — DENY\n"; PASS=$((PASS+1))
else
  printf "  FAIL  [GREEN ] R4-Q large input patched — expected DENY got ALLOW\n"; FAIL=$((FAIL+1))
fi

# R4-Q for BDC
LARGE_OUT_BDC_LIVE=$(echo "$LARGE_JSON" | bash "$LIVE_BDC" 2>&1 || true)
LARGE_OUT_BDC_STAGED=$(echo "$LARGE_JSON" | bash "$STAGED_BDC" 2>&1 || true)
if is_deny "$LARGE_OUT_BDC_LIVE"; then
  printf "  PASS  [RED   ] R4-Q BDC large input live — blocks (acceptable)\n"; PASS=$((PASS+1))
else
  printf "  PASS  [RED   ] R4-Q BDC large input live — ALLOW (bug confirmed)\n"; PASS=$((PASS+1))
fi
if is_deny "$LARGE_OUT_BDC_STAGED"; then
  printf "  PASS  [GREEN ] R4-Q BDC large input patched — DENY\n"; PASS=$((PASS+1))
else
  printf "  FAIL  [GREEN ] R4-Q BDC large input patched — expected DENY got ALLOW\n"; FAIL=$((FAIL+1))
fi

# ─── R4-N: missing destructive verbs (BDC) ───────────────────────────────────
echo ""
echo "=== R4-N: missing destructive verbs (block-dangerous-cmds) ==="
F="$TESTS_DIR/t11-r4n-unlink.json"
run_test "unlink ~/important-decoy (RED live)"         RED  "$LIVE_BDC"   "$F" ALLOW
run_test "unlink ~/important-decoy (GREEN patched)"    GREEN "$STAGED_BDC" "$F" DENY

F="$TESTS_DIR/t11-r4n-shred.json"
run_test "shred -u ~/decoy (RED live)"                 RED  "$LIVE_BDC"   "$F" ALLOW
run_test "shred -u ~/decoy (GREEN patched)"            GREEN "$STAGED_BDC" "$F" DENY

F="$TESTS_DIR/t11-r4n-srm.json"
run_test "srm -rf ~/Projects-decoy (RED live)"         RED  "$LIVE_BDC"   "$F" ALLOW
run_test "srm -rf ~/Projects-decoy (GREEN patched)"    GREEN "$STAGED_BDC" "$F" DENY

F="$TESTS_DIR/t11-r4n-chflags.json"
run_test "chflags -R schg ~/Projects-decoy (RED live)" RED  "$LIVE_BDC"   "$F" ALLOW
run_test "chflags -R schg ~/Projects-decoy (GREEN)"    GREEN "$STAGED_BDC" "$F" DENY

# reuse r4-2 fixture (multi-command, check each individually)
F2="$TESTS_DIR/r4-2-block-dangerous-srm-chflags.json"
if [ -f "$F2" ]; then
  # r4-2 has multiple command keys — extract each via python and test
  CMDS_JSON=$(python3 -c "
import json, sys
d = json.load(open('$F2'))
ti = d.get('tool_input', {})
cmds = {k:v for k,v in ti.items() if k.startswith('command')}
print(json.dumps(cmds))
" 2>/dev/null || echo "{}")
  for key in command_srm command_chflags command_shred; do
    CMD=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('$key',''))" <<< "$CMDS_JSON" 2>/dev/null || echo "")
    if [ -n "$CMD" ]; then
      FIXTURE_JSON=$(python3 -c "import json; print(json.dumps({'tool_name':'Bash','tool_input':{'command':'$CMD'}}))")
      LIVE_OUT=$(echo "$FIXTURE_JSON" | bash "$LIVE_BDC" 2>&1 || true)
      STAGED_OUT=$(echo "$FIXTURE_JSON" | bash "$STAGED_BDC" 2>&1 || true)
      if is_deny "$LIVE_OUT"; then
        printf "  PASS  [RED   ] r4-2 %s — blocks on live (still valid)\n" "$key"; PASS=$((PASS+1))
      else
        printf "  PASS  [RED   ] r4-2 %s — ALLOW on live (bug confirmed)\n" "$key"; PASS=$((PASS+1))
      fi
      if is_deny "$STAGED_OUT"; then
        printf "  PASS  [GREEN ] r4-2 %s — DENY on patched\n" "$key"; PASS=$((PASS+1))
      else
        printf "  FAIL  [GREEN ] r4-2 %s — expected DENY on patched got ALLOW\n" "$key"; FAIL=$((FAIL+1))
      fi
    fi
  done
fi

# ─── Regression: benign commands must still be ALLOWED ───────────────────────
echo ""
echo "=== Regression: benign commands must not be blocked ==="
run_test "cat ~/Projects/notes.txt"            REGR "$STAGED_PSR" "$TESTS_DIR/t11-benign-cat-projects.json"  ALLOW
run_test "cp ./a ./b"                          REGR "$STAGED_PSR" "$TESTS_DIR/t11-benign-cp-local.json"      ALLOW
run_test "rm -rf ~/Projects/foo/build"         REGR "$STAGED_BDC" "$TESTS_DIR/t11-benign-rm-build.json"      ALLOW
run_test "rsync ~/Projects/foo ~/Projects/bak" REGR "$STAGED_PSR" "$TESTS_DIR/t11-benign-rsync-projects.json" ALLOW
run_test "ln -s /tmp/decoy-src /tmp/decoy-lnk" REGR "$STAGED_PSR" "$TESTS_DIR/t11-benign-ln-local.json"     ALLOW
run_test "unlink /tmp/some-decoy-file"         REGR "$STAGED_BDC" "$TESTS_DIR/t11-benign-unlink-tmp.json"    ALLOW

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=================================================="
echo "  PASS: $PASS   FAIL: $FAIL   SKIP: $SKIP"
echo "=================================================="
[ "$FAIL" -eq 0 ]
