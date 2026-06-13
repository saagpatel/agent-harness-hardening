#!/bin/bash
# HARDENED protect-sensitive-reads.sh — tournament-11 patch
# Baseline: live hook as of 2026-06-12
#
# Changes in this version (tournament-11):
#   C2-canon   Path canonicalization pre-pass: collapse /./  and /<seg>/../
#              before the SENSITIVE regex so dot-segment bypasses are caught.
#   C2-symlink Deny `ln -s <target>` when the target matches SENSITIVE/SENSITIVE_DIR.
#   C1/R2-arc  Archive/copy read class: cp|rsync|tar|zip|cpio|pax|ditto|gpg|scp
#              denied when targeting a SENSITIVE path (closes the copy-then-read chain).
#   R4-O       Deny ANSI-C $'…' and $(printf …) obfuscation in sensitive-context cmds.
#   R4-Q       Length gate at top: inputs >128 KB are denied immediately.
set -uo pipefail

# R4-Q: length gate — deny oversized inputs before any processing.
# Finding R4-Q: a ~36 MB command string causes the hook to time-out and fail-open.
RAW_INPUT=$(cat)
INPUT_LEN=${#RAW_INPUT}
if [ "$INPUT_LEN" -gt 131072 ]; then
  jq -n --arg reason "Blocked: command input exceeds maximum allowed size (128 KB). Oversized payloads are not permitted." \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
  exit 0
fi

INPUT="$RAW_INPUT"
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: { hookEventName: "PreToolUse",
      permissionDecision: "deny", permissionDecisionReason: $reason }
  }'
  exit 0
}

READ_CMDS='(cat|bat|head|tail|less|more|view|file|hexdump|xxd|od|strings|nl|tac|column|dd|paste|tr|cut|rev|fold|expand|unexpand|base64|base32|split|csplit|fmt|pr|join|comm|sort|uniq|cmp|zcat|gzip|gunzip|bzcat|xzcat)'
LIST_CMDS='(ls|find|tree|stat|du|wc|md5|md5sum|shasum|sha1sum|sha256sum)'
TEXT_CMDS='(grep|egrep|fgrep|rg|ag|awk|sed|perl|python|python3|ruby|node)'
# C1/R2-arc: archive/copy commands that expose file content when targeting a sensitive path.
COPY_CMDS='(cp|rsync|tar|zip|cpio|pax|ditto|gpg|scp)'

HOME_ESC="${HOME//\//\\/}"
CMD_POS='(^|[;&|]|&&|\|\|)[[:space:]]*'

# Load the canonical lists from the shared policy (same file Codex reads). Fall back
# to built-ins if jq/file are unavailable — fail-safe, never fail-open.
POLICY="${CODEX_EGRESS_POLICY:-$HOME/.claude/mcp-gate-policy.json}"
_segs() { sed -E 's/\./\\./g' | paste -sd'|' -; }   # escape dots; / is literal in ERE
HOME_SEGS=""
DIR_SEGS=""
PROJ_SEGS=""
if command -v jq >/dev/null 2>&1 && [ -r "$POLICY" ]; then
  HOME_SEGS=$(jq -r '.sensitive_paths.home[]? // empty'                    "$POLICY" 2>/dev/null | _segs)
  DIR_SEGS=$( jq -r '.sensitive_paths.home_dirs[]? // empty'               "$POLICY" 2>/dev/null | _segs)
  PROJ_SEGS=$(jq -r '.sensitive_paths.project_secret_basenames[]? // empty' "$POLICY" 2>/dev/null | _segs)
fi
HOME_SEGS="${HOME_SEGS:-\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.docker/config\.json|\.kube|\.netrc|\.pypirc|\.npmrc|\.git-credentials|\.gem/credentials|\.anthropic|\.claude/\.tokens}"
DIR_SEGS="${DIR_SEGS:-\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.kube|\.claude/\.tokens}"
PROJ_SEGS="${PROJ_SEGS:-\.env|\.pem|\.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.npmrc|\.pypirc|\.netrc|\.git-credentials}"
SENSITIVE='(\$HOME|~|'"$HOME_ESC"')/('"$HOME_SEGS"')'
SENSITIVE_DIR='(\$HOME|~|'"$HOME_ESC"')/('"$DIR_SEGS"')'
# Project-level secret-file basenames (no ~/$HOME prefix).
PROJECT_SECRET='('"$PROJ_SEGS"')([^A-Za-z0-9]|$)'
# Strip documentation-only env templates so `cat .env.example` is allowed.
PROJ=$(printf '%s' "$COMMAND" | sed -E 's/[^[:space:]]*\.env\.(example|sample|template)[^[:space:]]*//g')

# ─── C2-canon: path canonicalization pre-pass ────────────────────────────────
# Finding C2 (HIGH): the live hook scans COMMAND as-is. `cat /Users/operator/./.ssh/id_rsa`
# and `cat /Users/operator/x/../.ssh/id_rsa` both evade the SENSITIVE regex because the
# literal path string doesn't match. We normalize dot-segments first, then run ALL
# existing checks on BOTH the raw string (defense-in-depth) and the canonical form.
#
# Implementation: iteratively collapse /<seg>/../ and /./  with sed until stable.
# We cannot use `realpath` here because the path may not exist at hook time (e.g. a
# future symlink target), and realpath would follow live symlinks anyway (see
# residual-limits note). Pure string normalization is the right tool here.
canonicalize() {
  local s="$1"
  local prev=""
  # Collapse /./  (single-dot segments) repeatedly.
  # Then collapse /non-slash-segment/../ (parent-directory references) repeatedly.
  # Loop until stable (handles nested sequences like /a/b/../../c).
  while [ "$s" != "$prev" ]; do
    prev="$s"
    s=$(printf '%s' "$s" | sed -E 's|/\./|/|g; s|/[^/]+/\.\./|/|g')
  done
  printf '%s' "$s"
}

COMMAND_CANON=$(canonicalize "$COMMAND")
PROJ_CANON=$(printf '%s' "$COMMAND_CANON" | sed -E 's/[^[:space:]]*\.env\.(example|sample|template)[^[:space:]]*//g')

# Helper: run a grep check against BOTH raw and canonical forms.
check_both() {
  local pattern="$1"
  local str_raw="$2"
  local str_canon="$3"
  echo "$str_raw"   | grep -qE "$pattern" && return 0
  echo "$str_canon" | grep -qE "$pattern" && return 0
  return 1
}

# ─── R4-O: obfuscation gate ───────────────────────────────────────────────────
# Finding R4-O: ANSI-C $'…' quoting and $(printf …) let an attacker embed a
# sensitive path as an escape sequence — grep's regex never sees the literal bytes.
# Deny any command containing these constructs when the command also touches a
# sensitive context (we check presence of the obfuscation anywhere in the command,
# then apply the full sensitive-path checks as normal on the raw/canonical strings;
# the obfuscation check is an additional early-exit for commands whose ONLY purpose
# could be to hide a path from the regex).
if echo "$COMMAND" | grep -qE "\\\$'[^']*\\\\[xX0-9][^']*'" || \
   echo "$COMMAND" | grep -qE '\$\(printf[[:space:]]'; then
  deny "Blocked: command contains ANSI-C \$'…' or \$(printf …) obfuscation. These constructs can encode sensitive paths as escape sequences to evade detection. Rewrite without escape-sequence encoding."
fi

# ─── 1+2: read / list / text commands targeting a sensitive path ──────────────
# (C2-canon applied: check both raw and canonical command strings)
if check_both "${CMD_POS}${READ_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: read-like command targeting a protected credential path."
fi
if check_both "${CMD_POS}${LIST_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: list-like command targeting a protected credential path."
fi
if check_both "${CMD_POS}${TEXT_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: text-processing command targeting a protected credential path."
fi

# ─── C1/R2-arc: archive/copy commands targeting a sensitive path ──────────────
# Finding C1-secondary / R2-I-chain (HIGH): cp/rsync/tar/zip/etc. can exfiltrate
# a credential directory to /tmp, then a subsequent allowed read exposes the content.
# The live hook only covers reader commands (cat/grep-style); this closes that gap.
if check_both "${CMD_POS}${COPY_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: archive/copy command targeting a protected credential path. Use environment variables to pass credentials; do not copy them to a staging location."
fi

# ─── C2-symlink: deny `ln -s <sensitive-target>` ─────────────────────────────
# Finding C2-symlink (HIGH): `ln -s ~/.ssh /tmp/z` followed by `cat /tmp/z/id_rsa`
# is a two-step exfil. The live hook catches neither step (step 1 is not a read;
# step 2 points to /tmp, not ~/.ssh). We close step 1 here: deny any `ln -s`
# whose non-flag operands include a SENSITIVE or SENSITIVE_DIR path as target.
# Strategy: strip `ln` command and flags, then check remaining tokens.
if echo "$COMMAND" | grep -qE "${CMD_POS}ln[[:space:]]"; then
  LN_ARGS=$(echo "$COMMAND" | sed -E 's/.*\bln[[:space:]]+(-[a-zA-Z ]*[[:space:]]+)?//')
  LN_ARGS_CANON=$(canonicalize "$LN_ARGS")
  if echo "$LN_ARGS"  | grep -qE "${SENSITIVE}" || \
     echo "$LN_ARGS"  | grep -qE "${SENSITIVE_DIR}" || \
     echo "$LN_ARGS_CANON" | grep -qE "${SENSITIVE}" || \
     echo "$LN_ARGS_CANON" | grep -qE "${SENSITIVE_DIR}"; then
    deny "Blocked: ln -s targeting a protected credential path. Creating a symlink to a sensitive directory enables two-step credential exfiltration."
  fi
fi

# ─── 3: input redirection FROM a sensitive path ───────────────────────────────
if check_both "<[[:space:]]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: input redirection from a protected credential path (e.g. 'cmd < ~/.ssh/key')."
fi
# ─── 4: bash \$(<file) / process-substitution read of a sensitive path ────────
if check_both "\\\$\\([[:space:]]*<[[:space:]]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: \$(<file) read of a protected credential path."
fi
if check_both "<\\([^)]*${SENSITIVE}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: process substitution reading a protected credential path."
fi
# ─── 5: cd into a protected credential directory ──────────────────────────────
if check_both "${CMD_POS}cd[[:space:]]+[^|&;]*${SENSITIVE_DIR}" "$COMMAND" "$COMMAND_CANON"; then
  deny "Blocked: changing directory into a protected credential directory."
fi

# ─── 6: project-level secret files (no ~/$HOME prefix) ───────────────────────
# (C2-canon applied via PROJ / PROJ_CANON)
if check_both "${CMD_POS}${READ_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ" "$PROJ_CANON"; then
  deny "Blocked: read-like command targeting a project secret file (.env / *.pem / *.key / id_rsa / .npmrc). Reference the value via an environment variable, or read the .env.example template."
fi
if check_both "${CMD_POS}${TEXT_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ" "$PROJ_CANON"; then
  deny "Blocked: text-processing command targeting a project secret file (.env / *.pem / *.key / id_rsa / .npmrc)."
fi
if check_both "<[[:space:]]*[^|&;]*${PROJECT_SECRET}" "$PROJ" "$PROJ_CANON"; then
  deny "Blocked: input redirection from a project secret file (e.g. 'cmd < .env')."
fi
if check_both "\\\$\\([[:space:]]*<[[:space:]]*[^)]*${PROJECT_SECRET}" "$PROJ" "$PROJ_CANON"; then
  deny "Blocked: \$(<file) read of a project secret file."
fi

# ─── archive/copy on project-level secret files ───────────────────────────────
# C1/R2-arc extended to project-local secrets (same copy-then-read chain risk).
if check_both "${CMD_POS}${COPY_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ" "$PROJ_CANON"; then
  deny "Blocked: archive/copy command targeting a project secret file."
fi

exit 0
