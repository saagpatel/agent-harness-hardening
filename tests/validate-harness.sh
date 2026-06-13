#!/bin/bash
# Test harness: runs harness-config-validate.sh logic against a staging payload.
# Replaces SETTINGS_LOCAL with a caller-supplied TEST_LOCAL_PATH so we never
# touch the live settings files. All other logic is identical to the original.
# Usage: TEST_LOCAL_PATH=<payload.json> SNAP_DIR=<dir> bash validate-harness.sh <<< <hook-event-json>

set -uo pipefail

# --- BEGIN configurable overrides for test harness ---
# Caller sets TEST_LOCAL_PATH to the staging payload; SNAP_DIR to a test snapshot dir.
TEST_LOCAL_PATH="${TEST_LOCAL_PATH:-}"
TEST_SNAP_DIR="${TEST_SNAP_DIR:-}"
# --- END configurable overrides ---

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
[ -z "$FILE" ] && exit 0

case "$FILE" in
  ~/*) FILE="${HOME}/${FILE#~/}" ;;
esac

SETTINGS_JSON="$HOME/.claude/settings.json"
DOT_CLAUDE_JSON="$HOME/.claude.json"
SETTINGS_LOCAL="$HOME/.claude/settings.local.json"

HARD_DENY_MIN=5
PERM_DENY_MIN=20
REQUIRED_DENY=(
  'Read(~/.ssh/**)'
  'Read(~/.aws/**)'
  'Read(~/.gnupg/**)'
  'Read(~/.config/op/**)'
  'Read(~/.config/gcloud/**)'
)

is_harness_file=false
case "$FILE" in
  "$SETTINGS_JSON"|"$DOT_CLAUDE_JSON"|"$SETTINGS_LOCAL"|"$HOME/.claude/CLAUDE.md")
    is_harness_file=true
    ;;
esac
[ "$is_harness_file" = false ] && exit 0

# TEST HARNESS OVERRIDE: redirect file reads to staging paths
if [ -n "$TEST_LOCAL_PATH" ] && [ "$FILE" = "$SETTINGS_LOCAL" ]; then
  FILE="$TEST_LOCAL_PATH"
  SETTINGS_LOCAL="$TEST_LOCAL_PATH"
fi

SNAPDIR="${TEST_SNAP_DIR:-$HOME/.claude/backups/auto-settings}"
BASENAME=$(basename "$FILE")
LOGFILE="/tmp/validate-harness-test.log"
mkdir -p "$(dirname "$LOGFILE")"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOGFILE" >&2; }

emit_block() {
  local reason="$1"
  echo "==> VALIDATOR DECISION: BLOCK" >&2
  echo "==> reason: $reason" >&2
  jq -n --arg reason "$reason" '{ decision: "block", continue: true, reason: $reason }'
}

emit_pass() {
  echo "==> VALIDATOR DECISION: PASS (no output = allow)" >&2
}

restore_latest() {
  local reason="$1"
  echo "==> ROLLBACK triggered: $reason" >&2
  emit_block "$reason"
  return
}

# Check 1: non-empty
if [ ! -s "$FILE" ]; then
  restore_latest "file is empty (0 bytes) after write"
  exit 0
fi

# Check 2: JSON validity
case "$BASENAME" in
  *.json)
    if ! jq empty "$FILE" 2>/dev/null; then
      restore_latest "invalid JSON after write"
      exit 0
    fi
    ;;
esac

# Check 3: structural + content checks
if [ "$FILE" = "$SETTINGS_JSON" ] || [ "$FILE" = "$SETTINGS_LOCAL" ] || [ "$FILE" = "$TEST_LOCAL_PATH" ]; then
  ACTIVE_FILE=""
  if [ -s "$SETTINGS_LOCAL" ] || [ -s "$TEST_LOCAL_PATH" ]; then
    ACTIVE_FILE="${TEST_LOCAL_PATH:-$SETTINGS_LOCAL}"
  elif [ -s "$SETTINGS_JSON" ]; then
    log "WARN: settings.local.json missing/empty — falling back to settings.json"
    ACTIVE_FILE="$SETTINGS_JSON"
  fi

  if [ -n "$ACTIVE_FILE" ]; then
    MERGED_FILE="$ACTIVE_FILE"
    # Simulate the merge: settings.json * settings.local.json (local overrides)
    if [ -s "$SETTINGS_JSON" ] && [ -s "$ACTIVE_FILE" ]; then
      MERGED_FILE=$(mktemp /tmp/cc-settings-merged.XXXXXX.json)
      jq -s '.[0] * .[1]' "$SETTINGS_JSON" "$ACTIVE_FILE" > "$MERGED_FILE" 2>/dev/null || MERGED_FILE="$ACTIVE_FILE"
      echo "==> Merge produced: deny_count=$(jq '(.permissions.deny//[])|length' "$MERGED_FILE"), hard_deny_count=$(jq '(.autoMode.hard_deny//[])|length' "$MERGED_FILE")" >&2
    fi
    cleanup_merged() { [ "$MERGED_FILE" != "$ACTIVE_FILE" ] && rm -f "$MERGED_FILE"; }

    hard_deny_count=$(jq '(.autoMode.hard_deny // []) | length' "$MERGED_FILE" 2>/dev/null || echo 0)
    echo "==> Check hard_deny: ${hard_deny_count} >= ${HARD_DENY_MIN}" >&2
    if [ "${hard_deny_count:-0}" -lt "$HARD_DENY_MIN" ]; then
      cleanup_merged
      restore_latest "autoMode.hard_deny dropped below ${HARD_DENY_MIN} (got: ${hard_deny_count})"
      exit 0
    fi

    perm_deny_count=$(jq '(.permissions.deny // []) | length' "$MERGED_FILE" 2>/dev/null || echo 0)
    echo "==> Check perm_deny: ${perm_deny_count} >= ${PERM_DENY_MIN}" >&2
    if [ "${perm_deny_count:-0}" -lt "$PERM_DENY_MIN" ]; then
      cleanup_merged
      restore_latest "permissions.deny dropped below ${PERM_DENY_MIN} (got: ${perm_deny_count})"
      exit 0
    fi

    echo "==> Check REQUIRED_DENY (5 credential rules)..." >&2
    for rule in "${REQUIRED_DENY[@]}"; do
      if ! jq -e --arg r "$rule" '((.permissions.deny // []) | index($r)) != null' "$MERGED_FILE" >/dev/null 2>&1; then
        cleanup_merged
        restore_latest "required credential-deny rule '$rule' missing after write"
        exit 0
      fi
      echo "==>   $rule: PRESENT" >&2
    done

    # Check 4: allow-list growth — compare FILE against snap of SAME BASENAME
    # Using TEST_SNAP_DIR so we use the real snap (the one taken before write)
    ACTUAL_SNAP_BASENAME=$(basename "$HOME/.claude/settings.local.json")
    LATEST_SNAP=$(ls -t "$SNAPDIR/${ACTUAL_SNAP_BASENAME}."*.bak 2>/dev/null | head -1)
    echo "==> Check allow-growth: snap=${LATEST_SNAP:-NONE}" >&2
    if [ -n "$LATEST_SNAP" ] && [ -f "$LATEST_SNAP" ]; then
      ADDED=$(jq -n --slurpfile new "$FILE" --slurpfile old "$LATEST_SNAP" \
        '(($new[0].permissions.allow // []) - ($old[0].permissions.allow // [])) | length' 2>/dev/null || echo 0)
      echo "==> allow entries added vs snap: ${ADDED}" >&2
      if [ "${ADDED:-0}" -gt 0 ]; then
        cleanup_merged
        restore_latest "permissions.allow gained ${ADDED} new entries (attack-surface expansion)"
        exit 0
      fi
    fi

    cleanup_merged
  fi
fi

emit_pass
echo '{}'
exit 0
