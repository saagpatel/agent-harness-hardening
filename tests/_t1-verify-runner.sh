#!/bin/bash
# Self-contained verifier for the T1/C1 protect-claude-writes patch.
# Run as `bash _t1-verify-runner.sh` so the inner guard invocations execute in
# this subprocess (NOT through the tool-layer PreToolUse hooks) — avoids the
# `L=~/.claude/hooks/...` + `>` self-trip on the live guard.
S="$HOME/Projects/fable-outputs/staging/tournament-11/protect-claude-writes.sh"
L="$HOME/.claude/hooks/protect-claude-writes.sh"
T="$HOME/Projects/fable-outputs/staging/tournament-11/tests"
verdict(){ printf '%s' "$1" | grep -q '"permissionDecision": *"deny"\|"decision": *"block"' && echo DENY || echo ALLOW; }

echo "=== staged patch present? ==="
[ -f "$S" ] && echo "yes: $S" || { echo "MISSING staged patch"; exit 3; }

echo "=== T1 (.tokens self-issuance) + C1 (swift) red->green ==="
for p in t1a-touch-token t1b-redirect-token r1-A-swift-write-claude r3-L-swift-write; do
  [ -f "$T/$p.json" ] || { echo "$p: (no fixture)"; continue; }
  lo=$(bash "$L" < "$T/$p.json" 2>/dev/null)
  so=$(bash "$S" < "$T/$p.json" 2>/dev/null)
  echo "$p: LIVE=$(verdict "$lo")  STAGED=$(verdict "$so")"
done

echo "=== regression (benign must stay ALLOW on staged) ==="
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"touch ~/Projects/_x"}}' > "$T/_benign-touch.json"
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"cat ~/.claude/settings.json"}}' > "$T/_benign-cat.json"
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"print(1)\""}}' > "$T/_benign-py.json"
for p in _benign-touch _benign-cat _benign-py; do
  so=$(bash "$S" < "$T/$p.json" 2>/dev/null)
  echo "$p: STAGED=$(verdict "$so")  (expect ALLOW)"
done
echo "=== done ==="
