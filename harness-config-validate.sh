#!/bin/bash
# PostToolUse Edit|Write — validate harness config writes. If the write
# corrupted the file (zeroed it, broke JSON, dropped required protections,
# expanded the allow-list), restore from the snapshot taken by
# harness-config-snapshot.sh.
#
# HARDENED 2026-06-07 (red-team Attack 3): the prior version checked only the
# COUNTS of permissions.deny / autoMode.hard_deny, so a write could strip the
# ~/.ssh / ~/.aws deny rules and pad the count back with junk, or add a
# permissions.allow entry, and pass. Now we also assert a canonical REQUIRED_DENY
# set is PRESENT and that permissions.allow did not GROW vs the pre-write snapshot.
#
# HARDENED 2026-06-12 (tournament-11):
#
#   R3-M (HIGH) — settings.local.json merge-asymmetry:
#     Previously, the allow-growth check compared $FILE (the just-written file)
#     against its own snapshot, not the merged config's snapshot. Also,
#     jq -s '.[0]*.[1]' lets settings.local.json REPLACE settings.json's deny
#     array (object-merge, not array-union). Fix: ALL structural checks (deny-count,
#     hard_deny-count, REQUIRED_DENY sentinels, allow-growth, deny-shrink) now run
#     against the MERGED config and compare a MERGED snapshot. We also add a second
#     REQUIRED_DENY sentinel set for non-credential Bash safety rules, and assert
#     that the merged deny array never LOSES an entry vs the pre-write merged snapshot.
#
#   R2-F (CRITICAL) — env policy redirection + hooks-structure invariant:
#     Any settings write that introduces or changes CODEX_EGRESS_POLICY,
#     MCP_GATE_POLICY, or CLAUDE_TOKEN_DIR triggers rollback — these keys
#     redirect the guard toolchain to a controlled path. Also: every PreToolUse
#     hook entry must keep timeout >= 5 (timeout→0 fails-open), and the guard
#     hook set must not shrink.
#
#   Class-13 (HIGH) — guard-toolchain hijack (see also lib/deny.sh):
#     This script pins JQ at top using the absolute path resolved before PATH
#     could be mutated. All jq invocations below use "$JQ".

set -uo pipefail

# [Class-13] Pin jq absolute path immediately — before any PATH-mutable work.
JQ="$(command -v jq)"
if [ -z "$JQ" ] || [ ! -x "$JQ" ]; then
  echo '{"decision":"block","continue":true,"reason":"harness-config-validate: jq not found — cannot validate settings write. Blocking as fail-safe."}' >&1
  exit 0
fi

INPUT=$(cat)
FILE=$("$JQ" -r '.tool_input.file_path // empty' <<< "$INPUT")
[ -z "$FILE" ] && exit 0

case "$FILE" in
  ~/*) FILE="${HOME}/${FILE#~/}" ;;
esac

SETTINGS_JSON="$HOME/.claude/settings.json"
DOT_CLAUDE_JSON="$HOME/.claude.json"
SETTINGS_LOCAL="$HOME/.claude/settings.local.json"

HARD_DENY_MIN=5
PERM_DENY_MIN=20

# [R3-M] Canonical credential-protection rules (must always survive a merge).
REQUIRED_DENY_CREDS=(
  'Read(~/.ssh/**)'
  'Read(~/.aws/**)'
  'Read(~/.gnupg/**)'
  'Read(~/.config/op/**)'
  'Read(~/.config/gcloud/**)'
)

# [R3-M] Canonical non-credential Bash safety rules (must also always survive).
REQUIRED_DENY_BASH=(
  'Bash(sudo *)'
  'Bash(rm -rf /*)'
  'Bash(rm -rf / *)'
  'Bash(chmod 777 *)'
)

# [R2-F] Protected env keys — introducing or changing any of these triggers rollback.
PROTECTED_ENV_KEYS=(
  'CODEX_EGRESS_POLICY'
  'MCP_GATE_POLICY'
  'CLAUDE_TOKEN_DIR'
)

# [R2-F] Minimum number of PreToolUse hook entries — guard set must not shrink.
PRETOOLUSE_HOOKS_MIN=8

is_harness_file=false
case "$FILE" in
  "$SETTINGS_JSON"|"$DOT_CLAUDE_JSON"|"$SETTINGS_LOCAL"|"$HOME/.claude/CLAUDE.md")
    is_harness_file=true
    ;;
esac
[ "$is_harness_file" = false ] && exit 0

SNAPDIR="$HOME/.claude/backups/auto-settings"
BASENAME=$(basename "$FILE")
LOGFILE="$HOME/.claude/logs/harness-config-validate.log"
mkdir -p "$(dirname "$LOGFILE")"

log() { echo "[$(date -Iseconds)] $*" >> "$LOGFILE"; }

emit_block() {
  local reason="$1"
  "$JQ" -n --arg reason "$reason" '{ decision: "block", continue: true, reason: $reason }'
}

restore_latest() {
  local reason="$1" latest
  latest=$(ls -t "$SNAPDIR/${BASENAME}."*.bak 2>/dev/null | head -1)
  if [ -z "$latest" ] || [ ! -f "$latest" ]; then
    log "VALIDATION FAILED on $FILE ($reason) but no snapshot found — NOT rolling back"
    osascript -e "display notification \"Validation failed on $BASENAME: $reason. NO snapshot to restore.\" with title \"Harness config corruption\"" 2>/dev/null
    emit_block "Harness config write to $BASENAME FAILED validation ($reason) and NO snapshot exists to roll back. The file may be corrupt. Inspect $FILE immediately and repair it by hand before continuing."
    return
  fi
  cp "$latest" "$FILE"
  log "ROLLBACK $FILE from $latest (reason: $reason)"
  osascript -e "display notification \"Rolled $BASENAME back from snapshot. Reason: $reason\" with title \"Harness config rollback\"" 2>/dev/null
  emit_block "Your edit to $BASENAME was automatically ROLLED BACK from snapshot — it failed validation: $reason. The file is now restored to its pre-edit state; your change was NOT applied. Re-do the edit correctly (preserve: hard_deny >= ${HARD_DENY_MIN}, permissions.deny >= ${PERM_DENY_MIN} AND all required credential-deny rules AND all required Bash safety rules, no new permissions.allow entries, no PROTECTED_ENV_KEYS changes, valid JSON)."
}

# Check 1: non-empty.
if [ ! -s "$FILE" ]; then
  restore_latest "file is empty (0 bytes) after write"
  exit 0
fi

# Check 2: JSON validity for .json files.
case "$BASENAME" in
  *.json)
    if ! "$JQ" empty "$FILE" 2>/dev/null; then
      restore_latest "invalid JSON after write"
      exit 0
    fi
    ;;
esac

# Check 3: structural + content checks for settings files.
if [ "$FILE" = "$SETTINGS_JSON" ] || [ "$FILE" = "$SETTINGS_LOCAL" ]; then

  # [R3-M] Build two merged configs — one with safe array-union, one with the
  # naive object-merge (*) that the old validator used.
  #
  # We run ALL security checks against BOTH. This catches:
  #   (a) Attacks that would fail even with the union merge (e.g., a local that
  #       somehow injects a deny entry with a bad value).
  #   (b) Attacks that would ONLY be caught via naive merge — e.g., a local with
  #       deny:[] that would silently replace the main deny list under the old *
  #       strategy. The naive merged config exposes what the old validator would
  #       have seen; our checks now catch what it missed.
  #
  # The union merge is the correct runtime merge strategy going forward; the naive
  # merge check is a defence-in-depth validator that catches legacy-path attacks.

  build_merged_union() {
    # Safe merge: array-union prevents local from shrinking deny/hard_deny.
    local s_json="$1" s_local="$2" out_file="$3"
    "$JQ" -n \
      --slurpfile j "$s_json" \
      --slurpfile l "$s_local" \
      '
      ($j[0] * $l[0])
      | .permissions.deny = (
          (($j[0].permissions.deny // []) + ($l[0].permissions.deny // []))
          | unique
        )
      | .autoMode.hard_deny = (
          (($j[0].autoMode.hard_deny // []) + ($l[0].autoMode.hard_deny // []))
          | unique
        )
      ' > "$out_file" 2>/dev/null
  }

  build_merged_naive() {
    # Old-strategy merge: local array REPLACES main array (attack surface).
    # We validate against this to detect what the old validator would have passed.
    local s_json="$1" s_local="$2" out_file="$3"
    "$JQ" -s '.[0] * .[1]' "$s_json" "$s_local" > "$out_file" 2>/dev/null
  }

  # Wrapper: build_merged always produces both files; callers check the naive one
  # in addition to the union one.
  build_merged() { build_merged_union "$@"; }

  # Determine active files.
  HAS_JSON=false; HAS_LOCAL=false
  [ -s "$SETTINGS_JSON" ]  && HAS_JSON=true
  [ -s "$SETTINGS_LOCAL" ] && HAS_LOCAL=true

  MERGED_FILE=""
  CLEANUP_MERGED=false
  if [ "$HAS_JSON" = true ] && [ "$HAS_LOCAL" = true ]; then
    MERGED_FILE=$(mktemp /tmp/cc-settings-merged.XXXXXX)
    CLEANUP_MERGED=true
    build_merged "$SETTINGS_JSON" "$SETTINGS_LOCAL" "$MERGED_FILE"
    if [ ! -s "$MERGED_FILE" ]; then
      # Fall back to whichever single file exists.
      rm -f "$MERGED_FILE"
      CLEANUP_MERGED=false
      MERGED_FILE="$SETTINGS_JSON"
    fi
  elif [ "$HAS_JSON" = true ]; then
    log "WARN: settings.local.json missing/empty — using settings.json as merged config"
    MERGED_FILE="$SETTINGS_JSON"
  elif [ "$HAS_LOCAL" = true ]; then
    log "WARN: settings.json missing/empty — using settings.local.json as merged config"
    MERGED_FILE="$SETTINGS_LOCAL"
  fi

  cleanup_merged() {
    [ "$CLEANUP_MERGED" = true ] && rm -f "$MERGED_FILE"
  }

  if [ -n "$MERGED_FILE" ] && [ -s "$MERGED_FILE" ]; then

    # ── Count checks on MERGED config (R3-M) ──────────────────────────────
    hard_deny_count=$("$JQ" '(.autoMode.hard_deny // []) | length' "$MERGED_FILE" 2>/dev/null || echo 0)
    if [ "${hard_deny_count:-0}" -lt "$HARD_DENY_MIN" ]; then
      cleanup_merged
      restore_latest "autoMode.hard_deny dropped below ${HARD_DENY_MIN} in MERGED config (got: ${hard_deny_count:-missing})"
      exit 0
    fi

    perm_deny_count=$("$JQ" '(.permissions.deny // []) | length' "$MERGED_FILE" 2>/dev/null || echo 0)
    if [ "${perm_deny_count:-0}" -lt "$PERM_DENY_MIN" ]; then
      cleanup_merged
      restore_latest "permissions.deny dropped below ${PERM_DENY_MIN} in MERGED config (got: ${perm_deny_count:-missing})"
      exit 0
    fi

    # ── Credential-deny sentinel (R3-M) ───────────────────────────────────
    for rule in "${REQUIRED_DENY_CREDS[@]}"; do
      if ! "$JQ" -e --arg r "$rule" '((.permissions.deny // []) | index($r)) != null' "$MERGED_FILE" >/dev/null 2>&1; then
        cleanup_merged
        restore_latest "required credential-deny rule '$rule' missing after write (content tamper — MERGED config check)"
        exit 0
      fi
    done

    # ── Bash safety sentinel (R3-M) ────────────────────────────────────────
    for rule in "${REQUIRED_DENY_BASH[@]}"; do
      if ! "$JQ" -e --arg r "$rule" '((.permissions.deny // []) | index($r)) != null' "$MERGED_FILE" >/dev/null 2>&1; then
        cleanup_merged
        restore_latest "required Bash safety deny rule '$rule' missing after write (MERGED config check)"
        exit 0
      fi
    done

    # ── Naive-merge safety check (R3-M core defence) ──────────────────────
    # Build a second merged config using the OLD jq -s '.[0]*.[1]' strategy
    # (object-merge, where local arrays REPLACE main arrays). Run all sentinel
    # and count checks against this naive merge too — it exposes what would
    # happen if the runtime ever uses the old merge path.
    #
    # This is the primary fix for R3-M: a settings.local.json with deny:[]
    # produces a naive-merged config with deny:[], which will fail the
    # REQUIRED_DENY checks and count checks here.
    if [ "$HAS_JSON" = true ] && [ "$HAS_LOCAL" = true ]; then
      NAIVE_MERGED=$(mktemp /tmp/cc-settings-naive.XXXXXX)
      build_merged_naive "$SETTINGS_JSON" "$SETTINGS_LOCAL" "$NAIVE_MERGED"
      if [ -s "$NAIVE_MERGED" ]; then
        naive_hard_deny_count=$("$JQ" '(.autoMode.hard_deny // []) | length' "$NAIVE_MERGED" 2>/dev/null || echo 0)
        if [ "${naive_hard_deny_count:-0}" -lt "$HARD_DENY_MIN" ]; then
          rm -f "$NAIVE_MERGED"; cleanup_merged
          restore_latest "R3-M: settings.local.json would reduce autoMode.hard_deny to ${naive_hard_deny_count} in naive merge — local file must not suppress main hard_deny (deny-override attack)"
          exit 0
        fi
        naive_perm_deny_count=$("$JQ" '(.permissions.deny // []) | length' "$NAIVE_MERGED" 2>/dev/null || echo 0)
        if [ "${naive_perm_deny_count:-0}" -lt "$PERM_DENY_MIN" ]; then
          rm -f "$NAIVE_MERGED"; cleanup_merged
          restore_latest "R3-M: settings.local.json would reduce permissions.deny to ${naive_perm_deny_count} in naive merge — local file must not suppress main deny array (deny-override attack)"
          exit 0
        fi
        for rule in "${REQUIRED_DENY_CREDS[@]}"; do
          if ! "$JQ" -e --arg r "$rule" '((.permissions.deny // []) | index($r)) != null' "$NAIVE_MERGED" >/dev/null 2>&1; then
            rm -f "$NAIVE_MERGED"; cleanup_merged
            restore_latest "R3-M: credential-deny rule '$rule' would be erased by naive merge — settings.local.json deny array suppresses main deny (deny-override attack)"
            exit 0
          fi
        done
        for rule in "${REQUIRED_DENY_BASH[@]}"; do
          if ! "$JQ" -e --arg r "$rule" '((.permissions.deny // []) | index($r)) != null' "$NAIVE_MERGED" >/dev/null 2>&1; then
            rm -f "$NAIVE_MERGED"; cleanup_merged
            restore_latest "R3-M: Bash safety deny rule '$rule' would be erased by naive merge — settings.local.json deny array suppresses main deny (deny-override attack)"
            exit 0
          fi
        done
      fi
      rm -f "$NAIVE_MERGED"
    fi

    # ── Merged snapshot for allow-growth + deny-shrink checks (R3-M) ──────
    # Build the merged snapshot from the latest pre-write backups.
    SNAP_JSON=$(ls -t "$SNAPDIR/settings.json."*.bak 2>/dev/null | head -1)
    SNAP_LOCAL=$(ls -t "$SNAPDIR/settings.local.json."*.bak 2>/dev/null | head -1)

    MERGED_SNAP=""
    CLEANUP_SNAP=false
    if [ -n "$SNAP_JSON" ] && [ -f "$SNAP_JSON" ] && [ -n "$SNAP_LOCAL" ] && [ -f "$SNAP_LOCAL" ]; then
      MERGED_SNAP=$(mktemp /tmp/cc-settings-merged-snap.XXXXXX)
      CLEANUP_SNAP=true
      build_merged "$SNAP_JSON" "$SNAP_LOCAL" "$MERGED_SNAP"
      [ ! -s "$MERGED_SNAP" ] && { rm -f "$MERGED_SNAP"; CLEANUP_SNAP=false; MERGED_SNAP=""; }
    elif [ -n "$SNAP_JSON" ] && [ -f "$SNAP_JSON" ]; then
      MERGED_SNAP="$SNAP_JSON"
    elif [ -n "$SNAP_LOCAL" ] && [ -f "$SNAP_LOCAL" ]; then
      MERGED_SNAP="$SNAP_LOCAL"
    fi

    cleanup_snap() {
      [ "$CLEANUP_SNAP" = true ] && rm -f "$MERGED_SNAP"
    }

    if [ -n "$MERGED_SNAP" ] && [ -s "$MERGED_SNAP" ]; then

      # [R3-M] allow-growth check: run against MERGED (not just $FILE).
      ADDED=$("$JQ" -n --slurpfile new "$MERGED_FILE" --slurpfile old "$MERGED_SNAP" \
        '(($new[0].permissions.allow // []) - ($old[0].permissions.allow // [])) | length' 2>/dev/null || echo 0)
      if [ "${ADDED:-0}" -gt 0 ]; then
        cleanup_snap; cleanup_merged
        restore_latest "permissions.allow gained ${ADDED} new entr(ies) in MERGED config after write (attack-surface expansion — review each addition manually)"
        exit 0
      fi

      # [R3-M] deny-shrink check (inverse of allow-growth): the merged deny
      # array must never LOSE entries vs the pre-write merged snapshot.
      REMOVED=$("$JQ" -n --slurpfile old "$MERGED_SNAP" --slurpfile new "$MERGED_FILE" \
        '(($old[0].permissions.deny // []) - ($new[0].permissions.deny // [])) | length' 2>/dev/null || echo 0)
      if [ "${REMOVED:-0}" -gt 0 ]; then
        cleanup_snap; cleanup_merged
        restore_latest "permissions.deny LOST ${REMOVED} entr(ies) in MERGED config after write (deny-shrink attack)"
        exit 0
      fi
    fi

    # Save MERGED_SNAP path before cleanup_snap destroys the file.
    SAVED_MERGED_SNAP="$MERGED_SNAP"
    cleanup_snap

    # ── R2-F: Protected env keys ───────────────────────────────────────────
    # Rollback if any write introduces or changes CODEX_EGRESS_POLICY,
    # MCP_GATE_POLICY, or CLAUDE_TOKEN_DIR in env.* — these redirect guards.
    # Compare against the latest pre-write file snapshots directly (not the
    # merged snap which may have been cleaned up). Check both snapshot files
    # so we catch a key injected in either.
    for key in "${PROTECTED_ENV_KEYS[@]}"; do
      if "$JQ" -e --arg k "$key" '.env[$k] != null' "$MERGED_FILE" >/dev/null 2>&1; then
        # Key is present post-write. Compare against pre-write snapshots.
        # Key is allowed only if it existed in BOTH the pre-write merged config
        # AND has the same value. We check against the saved merged snap if it
        # still exists; otherwise fall back to raw snapshots.
        OLD_VAL="__ABSENT__"
        if [ -n "$SAVED_MERGED_SNAP" ] && [ -s "$SAVED_MERGED_SNAP" ]; then
          OLD_VAL=$("$JQ" -r --arg k "$key" '.env[$k] // "__ABSENT__"' "$SAVED_MERGED_SNAP" 2>/dev/null || echo "__ABSENT__")
        else
          # No merged snap; check raw snapshot files.
          if [ -n "$SNAP_JSON" ] && [ -f "$SNAP_JSON" ]; then
            TMP_OLD=$("$JQ" -r --arg k "$key" '.env[$k] // "__ABSENT__"' "$SNAP_JSON" 2>/dev/null || echo "__ABSENT__")
            [ "$TMP_OLD" != "__ABSENT__" ] && OLD_VAL="$TMP_OLD"
          fi
          if [ "$OLD_VAL" = "__ABSENT__" ] && [ -n "$SNAP_LOCAL" ] && [ -f "$SNAP_LOCAL" ]; then
            TMP_OLD=$("$JQ" -r --arg k "$key" '.env[$k] // "__ABSENT__"' "$SNAP_LOCAL" 2>/dev/null || echo "__ABSENT__")
            [ "$TMP_OLD" != "__ABSENT__" ] && OLD_VAL="$TMP_OLD"
          fi
        fi
        NEW_VAL=$("$JQ" -r --arg k "$key" '.env[$k] // "__ABSENT__"' "$MERGED_FILE" 2>/dev/null || echo "__ABSENT__")
        if [ "$OLD_VAL" != "$NEW_VAL" ]; then
          cleanup_merged
          restore_latest "R2-F: protected env key '$key' was introduced or changed (old='${OLD_VAL}' → new='${NEW_VAL}') — redirecting guard toolchain via settings write is not permitted"
          exit 0
        fi
      fi
    done

    # ── R2-F: PreToolUse hooks count must not shrink ───────────────────────
    ptu_count=$("$JQ" '
      [ .hooks.PreToolUse // []
        | .[]
        | .hooks // []
        | .[]
      ] | length
    ' "$MERGED_FILE" 2>/dev/null || echo 0)
    if [ "${ptu_count:-0}" -lt "$PRETOOLUSE_HOOKS_MIN" ]; then
      cleanup_merged
      restore_latest "R2-F: PreToolUse hook count dropped to ${ptu_count} (minimum ${PRETOOLUSE_HOOKS_MIN}) — guard hook set must not shrink"
      exit 0
    fi

    # ── R2-F: Every PreToolUse hook must have timeout >= 5 ────────────────
    bad_timeout=$("$JQ" '
      [ .hooks.PreToolUse // []
        | .[]
        | .hooks // []
        | .[]
        | select((.timeout // 0) < 5)
      ] | length
    ' "$MERGED_FILE" 2>/dev/null || echo 0)
    if [ "${bad_timeout:-0}" -gt 0 ]; then
      cleanup_merged
      restore_latest "R2-F: ${bad_timeout} PreToolUse hook(s) have timeout < 5 — reducing timeout fails-open by causing hook to be skipped"
      exit 0
    fi

    cleanup_merged
  fi
fi

exit 0
