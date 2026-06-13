#!/bin/bash
# hooks/lib/deny.sh — canonical PreToolUse deny emitter.
# Source with: . "$HOME/.claude/hooks/lib/deny.sh"
#
# HARDENED 2026-06-12 (Class-13 — guard-toolchain hijack):
#   Prior version called bare `jq`, so a poisoned PATH (e.g. /tmp/fakebin/jq
#   that emits nothing or exits non-zero) would silently fail-open — the hook
#   sourcing this file would produce no deny output and CC would allow the call.
#
#   Fix: pin JQ to the absolute path resolved at source time, BEFORE any
#   PATH-mutable work in the sourcing hook. If jq is not found or not
#   executable, fall back to a hardcoded printf that emits a valid deny JSON
#   without invoking jq at all — ensuring we NEVER fail-open even if the entire
#   jq binary is replaced or missing.
#
#   NOTE for hook authors: each hook that sources this lib should ALSO pin
#     JQ="$(command -v jq)"
#   at its own top — before any external command that could mutate PATH —
#   and pass "$JQ" explicitly where jq is called outside of deny().
#   lib/deny.sh is the single highest-leverage hardening point because every
#   hook that sources it inherits the fixed deny() function.

# [Class-13] Resolve jq absolute path bypassing PATH entirely.
# We check a hardcoded allowlist of known-safe locations before falling back
# to PATH resolution. This prevents a poisoned PATH from substituting a fake jq.
# The sourcing hook's JQ variable takes precedence only if it is an absolute
# path pointing to an executable — a bare name like "jq" from a poisoned hook
# is rejected.
_DENY_JQ=""
_resolve_jq() {
  # 1. If caller already pinned an absolute-path JQ, trust it.
  if [ -n "${JQ:-}" ] && [[ "${JQ}" == /* ]] && [ -x "${JQ}" ]; then
    echo "${JQ}"; return
  fi
  # 2. Check hardcoded safe locations (bypasses PATH entirely).
  local candidate
  for candidate in \
    /opt/homebrew/bin/jq \
    /usr/local/bin/jq \
    /usr/bin/jq \
    /bin/jq \
    /opt/local/bin/jq \
    /nix/var/nix/profiles/default/bin/jq; do
    if [ -x "$candidate" ]; then
      echo "$candidate"; return
    fi
  done
  # 3. Last resort: PATH search — acceptable if no known location exists,
  #    but only accept the result if it is an absolute path (not a shell alias).
  local found
  found=$(command -v jq 2>/dev/null || true)
  if [ -n "$found" ] && [[ "$found" == /* ]] && [ -x "$found" ]; then
    echo "$found"; return
  fi
  # Not found anywhere safe.
  echo ""
}
_DENY_JQ="$(_resolve_jq)"

deny() {
  local reason="$1"

  if [ -n "$_DENY_JQ" ] && [ -x "$_DENY_JQ" ]; then
    # Normal path: emit deny JSON via pinned absolute-path jq.
    "$_DENY_JQ" -n --arg reason "$reason" '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: $reason
      }
    }'
  else
    # [Class-13] Hard fallback: jq is absent or not executable (toolchain hijack
    # attempted). Emit a minimal valid deny JSON via printf — no external binary
    # required. Escapes only the characters that would break JSON string parsing.
    # This is intentionally minimal: safety over elegance.
    local escaped_reason
    # Escape backslash, double-quote, and control chars that break JSON strings.
    escaped_reason=$(printf '%s' "$reason" \
      | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' 2>/dev/null \
      || printf '%s' "$reason")
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
      "$escaped_reason"
  fi

  exit 0
}
