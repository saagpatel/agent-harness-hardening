#!/bin/bash
# Block catastrophically destructive shell commands
# HARDENED 2026-06-07: DANGER_RE now matches quoted "$HOME"/'$HOME' and a new
# check catches relative whole-cwd wipes (rm -rf . / ./ / *). Closes red-team
# finding 2b (partial). Residual: `D=$HOME; rm -rf $D` variable indirection is
# not statically detectable - backstopped by permissions.deny + operator review.
#
# tournament-11 additions:
#   R4-Q   Length gate at top: inputs >128 KB denied immediately (fail-safe).
#   R4-N   Missing destructive verbs: unlink, shred, srm, gshred, chflags schg.
set -euo pipefail

# R4-Q: length gate — deny oversized inputs before any processing.
# Finding R4-Q: a ~36 MB command causes hook timeout → fail-open.
RAW_INPUT=$(cat)
INPUT_LEN=${#RAW_INPUT}
if [ "$INPUT_LEN" -gt 131072 ]; then
  jq -n --arg reason "Blocked: command input exceeds maximum allowed size (128 KB). Oversized payloads are not permitted." \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
  exit 0
fi

INPUT="$RAW_INPUT"

. "$HOME/.claude/hooks/lib/deny.sh"

# Null bytes in JSON tool_input.command cause bash command substitution to
# truncate COMMAND at the null byte, silently dropping everything after it.
if echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    cmd = d.get('tool_input', {}).get('command', '')
    sys.exit(1 if chr(0) in cmd else 0)
except Exception:
    sys.exit(0)
" 2>/dev/null; then
  : # no null bytes - proceed normally
else
  deny "Blocked: command string contains a null byte. This is not a valid shell command."
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

# Block rm targeting root, home, or shallow home subdirs.
if echo "$COMMAND" | grep -qE '\brm\b.+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)'; then
  HOME_ESC=""
  if [ -n "${HOME:-}" ]; then
    HOME_ESC=$(printf '%s' "$HOME" | sed 's/[][\/.^$*+?(){}|]/\\&/g')
  fi
  # HARDENED: treat a quote as a valid path-boundary separator so quoted home
  # tokens (rm -rf "$HOME") are caught.
  SHELL_SEP='([[:space:]]|;|&|\||"|'"'"'|$)'
  # Build the dangerous-shape pattern. Targets at depth <= 1:
  #   bare / | ~ | $HOME | $HOME/X | /Users/operator | /Users/operator/X
  # HARDENED: allow an optional leading quote before the path token.
  DANGER_RE="(^|[[:space:]]|\"|')((/|~|\\\$HOME"
  [ -n "$HOME_ESC" ] && DANGER_RE="$DANGER_RE|$HOME_ESC"
  DANGER_RE="$DANGER_RE)(/[^/[:space:];&|\"']+)?/?)${SHELL_SEP}"
  # Split compound commands and check only the rm-containing segment.
  RM_HIT=0
  while IFS= read -r seg; do
    if echo "$seg" | grep -qE '\brm\b.+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)'; then
      # Block if the segment targets a depth<=1 home/root shape OR a relative
      # whole-current-directory wipe (. / ./ / *).
      if echo "$seg" | grep -qE "$DANGER_RE" \
         || echo "$seg" | grep -qE '\brm\b.+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)[[:space:]]+(\.|\./|\*)[[:space:]]*$'; then
        RM_HIT=1; break
      fi
    fi
  done < <(printf '%s\n' "$COMMAND" | sed 's/&&/\n/g; s/||/\n/g; s/;/\n/g')
  if [ "$RM_HIT" -eq 1 ]; then
    deny "Blocked: rm targeting root, home, a depth-1 subdir of home, or the whole current directory (. / ./ / *). Scope your delete to an explicit deeper path (depth >= 2 like ~/Projects/foo)."
  fi
fi
if echo "$COMMAND" | grep -qE '\brm\b.+(-[a-zA-Z]*r[a-zA-Z]*|--recursive).*(\/usr|\/etc|\/bin|\/sbin|\/lib|\/var|\/sys|\/proc|\/boot)\b'; then
  deny "Blocked: rm targeting system directory. This operation could damage the OS."
fi

# ─── R4-N: missing destructive verbs ─────────────────────────────────────────
# Finding R4-N (MED): the live hook only checks rm for destructive file removal.
# The following commands are equally or more destructive but were not covered:
#
#   unlink <path>   — low-level single-file delete (no -r flag needed, silently bypasses rm checks)
#   shred  -u …    — overwrite + delete (irrecoverable; POSIX); gshred is the GNU alias on macOS
#   srm    …       — Apple's secure-remove; removed from macOS 10.14+ but installable via brew
#   chflags -R schg ~/…  — sets the system-immutable flag recursively; makes a directory tree
#                          undeletable even by root (requires boot to single-user to undo), used
#                          as a denial-of-rollback attack: brick the tree, then rm can't clean up.
#
# Depth-1 HOME path guard (same shape as rm checks): only deny when targeting
# shallow home paths to keep the signal-to-noise ratio high. `unlink` is a
# single-file command so we deny it whenever it names a depth-1 home path.
HOME_ESC_N=""
if [ -n "${HOME:-}" ]; then
  HOME_ESC_N=$(printf '%s' "$HOME" | sed 's/[][\/.^$*+?(){}|]/\\&/g')
fi
SHALLOW_HOME="(~|\\\$HOME|${HOME_ESC_N})(/[^/[:space:];&|\"']+)?/?"

# unlink: single-file, any depth ≤ 1 home path is dangerous.
if echo "$COMMAND" | grep -qE "\bunlink[[:space:]]+[^;|&]*${SHALLOW_HOME}"; then
  deny "Blocked: unlink targeting home or a depth-1 home subdirectory. Use rm on a specific deeper path."
fi

# shred / gshred: irrecoverable overwrite-delete; deny any home-anchored target.
if echo "$COMMAND" | grep -qE "\b(shred|gshred)\b[[:space:]]+[^;|&]*${SHALLOW_HOME}"; then
  deny "Blocked: shred/gshred targeting home or a depth-1 home subdirectory. Secure-deletion of shallow home paths is not permitted."
fi

# srm: Apple secure-remove (equivalent risk to shred).
if echo "$COMMAND" | grep -qE "\bsrm\b[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*[[:space:]]+[^;|&]*${SHALLOW_HOME}"; then
  deny "Blocked: srm -r targeting home or a depth-1 home subdirectory. Scope to a deeper path."
fi
# srm without -r on a shallow home path (single-file secure-delete still dangerous at root level).
if echo "$COMMAND" | grep -qE "\bsrm\b[[:space:]]+[^;|&]*${SHALLOW_HOME}[[:space:]]*$"; then
  deny "Blocked: srm targeting home or a depth-1 home subdirectory."
fi

# chflags -R schg: setting the system-immutable flag recursively can brick a tree.
# Deny when the target is a shallow home path. -R with schg is the dangerous combo.
if echo "$COMMAND" | grep -qE "\bchflags\b[[:space:]]+(-R[[:space:]]+schg|schg[[:space:]]+-R)[[:space:]]+[^;|&]*${SHALLOW_HOME}"; then
  deny "Blocked: chflags -R schg targeting home or a depth-1 home subdirectory. Setting the system-immutable flag recursively on a home directory can make the tree irrecoverable without single-user mode."
fi

# Block disk formatting
if echo "$COMMAND" | grep -qE '\b(mkfs|fdisk|diskutil\s+eraseDisk|wipefs)\b'; then
  deny "Blocked: disk formatting command. This would destroy all data on the target device."
fi

# Block dd writing to disk devices
if echo "$COMMAND" | grep -qE '\bdd\b.*\bof=/dev/(sd[a-z]|nvme|disk[0-9]|hd[a-z])\b'; then
  deny "Blocked: dd writing to a disk device. This would overwrite the device completely."
fi

# Block kill -9 -1 (kill all user processes)
if echo "$COMMAND" | grep -qE '\bkill\s+(-9\s+-1|-1\s+-9|--signal\s+9\s+-1)\b'; then
  deny "Blocked: kill -9 -1 terminates all your processes. Be more specific about which process to kill."
fi

# Block fork bomb patterns
if echo "$COMMAND" | grep -qE ':\(\)\{.*:\|:.*\}'; then
  deny "Blocked: fork bomb pattern detected."
fi

exit 0
