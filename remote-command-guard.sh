#!/bin/bash
# remote-command-guard.sh — semantic RCE guard (pipe-to-shell + eval patterns).
# Parity sibling of bash-egress-guard.sh: covers SEMANTIC risks that apply even to
# allow-listed hosts (e.g. raw.githubusercontent.com is an allowed fetch host but
# executing its content is still an RCE risk).
#
# HARDENED tournament-11:
#   R2-G-B (MED)  — eval of quoted/process-substitution remote content
#   R2-G-D (MED)  — pipe-to-unknown-interpreter (open-world deny, primary in bash-egress;
#                   this guard remains for defense-in-depth on the semantic pattern)
#
# KEPT from H3 trimmed version:
#   - curl|wget pipe-to-shell RCE check (R2-G-D semantic layer)
#   - eval of downloaded content (R2-G-B expanded)
#
# REMOVED (H3, unchanged):
#   - SSH block — covered by bash-egress-guard.sh R10 + network-verb gate
#   - curl/wget @file-exfil block — covered by bash-egress-guard.sh allow-list gate
#
# STATUS: STAGED / NOT APPLIED — ~/.claude/hooks is hard-deny. Operator applies via `!`.
# Original: ~/.claude/hooks/remote-command-guard.sh (back up before applying).
set -uo pipefail
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

. "$HOME/.claude/hooks/lib/deny.sh"

# ── R2-G-D: pipe-to-shell (semantic / defense-in-depth layer) ────────────────
# Primary detection is the open-world check in bash-egress-guard.sh. This guard
# is retained as a defense-in-depth semantic pattern that fires even when the
# primary guard is bypassed (e.g. policy file temporarily missing).
# Closed list replaced with open-world: deny any pipe target that is not a known
# safe data-transform filter.
#
# Safe data-transform filters (no code execution capability):
SAFE_PIPE_FILTERS=' grep jq awk sed sort uniq head tail tee cat wc tr cut '
# [R2-G-D]
if echo "$COMMAND" | grep -qiE '\b(curl|wget)\b.*\|'; then
  PIPE_DEST=$(echo "$COMMAND" | grep -oiE '\b(curl|wget)\b[^|]*\|[[:space:]]*[A-Za-z0-9_/.-]+' \
              | sed -E 's/.*\|[[:space:]]*//' | tr '[:upper:]' '[:lower:]' | grep -oE '^[A-Za-z0-9_/.-]+')
  while IFS= read -r pd; do
    [ -z "$pd" ] && continue
    pbase=$(basename "$pd")
    case "$SAFE_PIPE_FILTERS" in
      *" $pbase "*) ;;   # safe data-transform — pass
      *)
        deny "Blocked (remote-command-guard R2-G-D): curl/wget piped to '$pd' which is not on the safe-filter allowlist (grep/jq/awk/sed/…). Download first and inspect before running." ;;
    esac
  done <<< "$PIPE_DEST"
fi

# REMOVED (H3): SSH block — covered by bash-egress-guard.sh R10 + network-verb gate.

# ── R2-G-B: eval of remote content (expanded) ────────────────────────────────
# Original check: eval $( ... ) unquoted.
# Expanded to catch:
#   1. eval "$(...)" / eval '$(...)'    — quoted command substitution
#   2. source <(curl|wget …)            — process substitution source
#   3. . <(curl|wget …)                 — dot-source process substitution
# All three execute remote content in the current shell without a file on disk,
# bypassing any path-based inspection gate.
# [R2-G-B]

# Pattern 1: eval $(...) — original, kept
if echo "$COMMAND" | grep -qE '\beval\s*\$\((curl|wget)\b'; then
  deny "Blocked (remote-command-guard R2-G-B): eval of remote content is a remote code execution risk."
fi

# Pattern 2: eval "$(...)" or eval '$(...)'  — quoted command substitution
# [R2-G-B]
if echo "$COMMAND" | grep -qE '\beval\s*["'"'"']\s*\$\((curl|wget)\b'; then
  deny "Blocked (remote-command-guard R2-G-B): eval of quoted remote command substitution is a remote code execution risk."
fi

# Pattern 3: source <(curl|wget …) or . <(curl|wget …)  — process-substitution source
# [R2-G-B]
if echo "$COMMAND" | grep -qE '\b(source|\.)(\s+)<\((curl|wget)\b'; then
  deny "Blocked (remote-command-guard R2-G-B): source/. of a process substitution from curl/wget is a remote code execution risk."
fi

# REMOVED (H3): curl/wget @file-exfil block — covered by bash-egress-guard.sh
# allow-list gate (stricter: host-level deny regardless of curl flag shape).

exit 0
