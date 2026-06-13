#!/usr/bin/env bash
# harness-drift-check.sh — pre-apply drift guard for staged harness patches.
#
# WHY THIS EXISTS (session-11 lesson, twice over): a staged patch is a *snapshot*.
# If the live target advances out-of-band after the snapshot freezes, a blind
# `cp staged -> live` silently REVERTS that out-of-band work. (Today: the frozen
# Codex hook predated F2/F9 being added live; a cp would have dropped them.)
# Splice-based installers are immune; cp-based installers are NOT — so run this
# FIRST and refuse to cp anything that comes back DIVERGED.
#
# It is read-only. For each (staged, live) pair it reports one of:
#   IDENTICAL  staged == live                      -> apply is a no-op
#   AHEAD      live-only lines == 0 (pure adds)     -> cp is SAFE
#   DIVERGED   live has lines staged lacks          -> cp would REVERT live work  [DANGER]
#   NEW        live target absent                   -> cp would create it
#   MISSING    staged file absent                   -> nothing to apply
#
# Exit 0 if nothing DIVERGED; 1 if any pair DIVERGED (so it can gate an installer);
# 2 on usage error.
#
# Usage:
#   bash harness-drift-check.sh                      # tournament-11 cp-based CC preset
#   bash harness-drift-check.sh <staged> <live> ...  # explicit pairs
set -uo pipefail

STAGING="$(cd "$(dirname "$0")" && pwd)"
HOOKS="$HOME/.claude/hooks"
LIBDIR="$HOOKS/lib"

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }

# The cp-based CC patch map (mirrors apply-tournament-11.sh). The Codex hook is
# deliberately NOT listed: it is splice-managed (codex-t11-splice.py) and therefore
# drift-immune — this guard is only meaningful for the cp-based surface.
preset_pairs(){
  cat <<EOF
$STAGING/protect-claude-writes.sh|$HOOKS/protect-claude-writes.sh
$STAGING/protect-sensitive-reads.sh|$HOOKS/protect-sensitive-reads.sh
$STAGING/block-dangerous-cmds.sh|$HOOKS/block-dangerous-cmds.sh
$STAGING/mcp-guard.sh|$HOOKS/mcp-guard.sh
$STAGING/confirm-token-required.sh|$HOOKS/confirm-token-required.sh
$STAGING/bash-egress-guard.sh|$HOOKS/bash-egress-guard.sh
$STAGING/remote-command-guard.sh|$HOOKS/remote-command-guard.sh
$STAGING/harness-config-validate.sh|$HOOKS/harness-config-validate.sh
$STAGING/task-completed-verify.sh|$HOOKS/task-completed-verify.sh
$STAGING/mcp-audit-log.sh|$HOOKS/mcp-audit-log.sh
$STAGING/semgrep-autoscan.sh|$HOOKS/semgrep-autoscan.sh
$STAGING/deny.sh|$LIBDIR/deny.sh
$STAGING/mcp-gate-policy.json|$HOME/.claude/mcp-gate-policy.json
EOF
}

# Build the (staged|live) work list from args or the preset.
PAIRS=()
if [ "$#" -eq 0 ]; then
  while IFS= read -r line; do [ -n "$line" ] && PAIRS+=("$line"); done < <(preset_pairs)
elif [ $(( $# % 2 )) -eq 0 ]; then
  while [ "$#" -gt 0 ]; do PAIRS+=("$1|$2"); shift 2; done
else
  red "ABORT: explicit pairs must be given as <staged> <live> [<staged> <live> ...]"
  exit 2
fi

classify(){ # $1 staged  $2 live  -> echoes STATUS<TAB>detail
  local staged="$1" live="$2"
  [ -f "$staged" ] || { printf 'MISSING\t(staged file absent)\n'; return; }
  [ -f "$live" ]   || { printf 'NEW\t(live target absent — cp would create)\n'; return; }
  # command diff bypasses any `diff`->delta alias (delta emits no ^</^> lines).
  local d liveonly stagedonly
  d="$(command diff "$live" "$staged" 2>/dev/null)"
  liveonly="$(printf '%s\n' "$d" | grep -c '^<')"
  stagedonly="$(printf '%s\n' "$d" | grep -c '^>')"
  if [ "$liveonly" -eq 0 ] && [ "$stagedonly" -eq 0 ]; then
    printf 'IDENTICAL\t(applied/unchanged)\n'
  elif [ "$liveonly" -eq 0 ]; then
    printf 'AHEAD\t(+%s staged-only lines, 0 live-only — cp SAFE)\n' "$stagedonly"
  else
    printf 'DIVERGED\t(%s live-only lines a cp would DELETE; +%s staged-only)\n' "$liveonly" "$stagedonly"
  fi
}

echo "=== harness drift check (read-only) ==="
diverged=0
for pair in "${PAIRS[@]}"; do
  staged="${pair%%|*}"; live="${pair##*|}"
  IFS=$'\t' read -r status detail < <(classify "$staged" "$live")
  name="$(basename "$live")"
  case "$status" in
    DIVERGED) red  "  DIVERGED   $name  — $detail"; diverged=$((diverged+1));;
    AHEAD)    ylw  "  AHEAD      $name  — $detail";;
    NEW)      ylw  "  NEW        $name  — $detail";;
    MISSING)  ylw  "  MISSING    $name  — $detail";;
    *)        grn  "  IDENTICAL  $name";;
  esac
done

echo ""
if [ "$diverged" -ne 0 ]; then
  red "RESULT: $diverged target(s) DIVERGED — DO NOT cp these (live has work the snapshot lacks)."
  red "        Reconcile by splicing onto current live, or refresh the snapshot from live, then re-check."
  exit 1
fi
grn "RESULT: no divergence — every staged file is identical to or a clean superset of live."
exit 0
