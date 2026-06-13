#!/bin/bash
# Gate certain destructive Bash patterns behind an operator-issued
# confirmation token. Closes the "are you sure?" gap from the redteam
# report (single-turn cold sessions ask for confirmation but proceed
# if the upstream prompt simply says "yes" — that's not a real block).
#
# Patterns that REQUIRE a token even when the simpler shape regexes
# would let them through:
#   - find ... -exec rm ...
#   - find ... -delete
#   - kubectl delete (any non-namespace target)
#   - git reset --hard
#   - git push --force / --force-with-lease (any branch)
#   - rm -rf at depth ≥ 2 under $HOME (the simple shape regex allows
#     these; this hook still wants a token for them when they touch
#     real project directories)
#
# Token flow (C5-aware):
#   1. Hook denies with instructions: "run claude-confirm in your terminal"
#   2. Operator runs `claude-confirm` (bare) or `claude-confirm <class>`
#      (scoped) — token file named <hex> or <hex>.<class> is created.
#   3. Operator pastes token to agent
#   4. Agent retries with `CONFIRM=<token> <original-command>`
#   5. Hook validates token (C5): prefers a scoped token whose class matches
#      the operation; falls back to a bare legacy token. Token is consumed
#      single-use (atomic mv).
#
# C5 — TOOL-SCOPED TOKENS (validator side):
#   Token files may be named <hex> (legacy, any class) OR <hex>.<opclass>.
#   This hook extracts the class from the trigger (see TRIGGER_CLASS below)
#   and prefers a token with a matching .<opclass> suffix.  A bare <hex>
#   token is accepted as a fallback only if no matching scoped token exists.
#   Backward compatibility: operators using the old unscoped claude-confirm
#   workflow are unaffected.  Forward path: update claude-confirm to emit
#   scoped tokens by default (issuer-side change, not in scope here).
#   TRADEOFF: bare token fallback means a single unscoped token still
#   authorizes any gated command class.  The tradeoff is accepted for
#   migration safety; remove the fallback once all issuers emit scoped tokens.

set -uo pipefail
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

TOKEN_DIR="$HOME/.claude/.tokens"

. "$HOME/.claude/hooks/lib/deny.sh"

# Returns 0 (true) if a recursive `rm` appears as an actual command, i.e. the
# recursive flag is in FLAG POSITION — not merely a substring of some path.
#
# Bug fixed 2026-05-30: the old test was
#   grep -qE '\brm\b.+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)'
# which scanned the whole command string, so a path segment like `-probe`,
# `my-project`, or `node_modules/.cache-rust` matched `-[a-zA-Z]*r[a-zA-Z]*`
# and a plain `rm -f` was wrongly treated as recursive (see
# feedback_confirm_token_probe_bug.md). We now split on shell separators and,
# within each rm-containing segment, only count `-...r...` / `--recursive`
# tokens that are genuine flag WORDS (start with `-`, occur before the `--`
# end-of-options marker, and are not the value of another option).
has_recursive_rm() {
  local cmd="$1"
  local seg
  while IFS= read -r seg; do
    # Tokenize the segment on whitespace; walk tokens looking for `rm` then a
    # recursive flag word before any `--` end-of-options marker.
    # shellcheck disable=SC2086
    set -- $seg
    local saw_rm=0 end_opts=0 tok
    for tok in "$@"; do
      if [ "$saw_rm" -eq 0 ]; then
        [ "$tok" = "rm" ] && saw_rm=1
        continue
      fi
      # After we've seen `rm`:
      if [ "$end_opts" -eq 1 ]; then
        continue   # everything after `--` is a path, never a flag
      fi
      case "$tok" in
        --) end_opts=1 ;;
        --recursive) return 0 ;;
        -- ) end_opts=1 ;;
        -*r*|-*R*)
          # A short-flag cluster containing r/R (e.g. -rf, -fr, -R). Must start
          # with a single dash and contain only flag letters — this excludes
          # path args (which don't start with `-`) entirely, since we only get
          # here for tokens beginning with `-`.
          case "$tok" in
            --*) : ;;                 # long option that isn't --recursive: ignore
            -[a-zA-Z]*) return 0 ;;   # short flag cluster with r/R → recursive
          esac
          ;;
      esac
    done
  done < <(printf '%s\n' "$cmd" | sed 's/&&/\n/g; s/||/\n/g; s/;/\n/g; s/|/\n/g')
  return 1
}

# Detect destructive patterns this hook owns.
needs_token=false
trigger=""
TRIGGER_CLASS="generic"  # C5: operation class for scoped-token preference

# find with -exec rm or -delete
if echo "$COMMAND" | grep -qE '\bfind\b[^|&;]*-(exec[[:space:]]+rm\b|delete\b)'; then
  needs_token=true
  trigger="find ... -exec rm / -delete"
  TRIGGER_CLASS="find_delete"
fi

# git push --force / --force-with-lease
if echo "$COMMAND" | grep -qE '\bgit[[:space:]]+push[[:space:]][^|&;]*(--force\b|-f\b|--force-with-lease\b)'; then
  needs_token=true
  trigger="git push --force"
  TRIGGER_CLASS="github_write"
fi

# git reset --hard
if echo "$COMMAND" | grep -qE '\bgit[[:space:]]+reset[[:space:]][^|&;]*--hard\b'; then
  needs_token=true
  trigger="git reset --hard"
  TRIGGER_CLASS="git_reset_hard"
fi

# kubectl delete
if echo "$COMMAND" | grep -qE '(^|[;&|]|&&|\|\|)[[:space:]]*kubectl[[:space:]]+delete\b'; then
  needs_token=true
  trigger="kubectl delete"
  TRIGGER_CLASS="kubectl_delete"
fi

# heroku destroy / fly destroy
if echo "$COMMAND" | grep -qE '(^|[;&|]|&&|\|\|)[[:space:]]*(heroku|fly|flyctl)[[:space:]]+(destroy|apps:destroy|apps[[:space:]]+destroy)\b'; then
  needs_token=true
  trigger="cloud app destroy"
  TRIGGER_CLASS="cloud_destroy"
fi

# rm -rf at depth ≥ 2 under $HOME — block-dangerous-cmds.sh allows these;
# this hook adds a token requirement so real project directories require
# operator confirmation. Excluded: build/cache/tmp paths that are safe to
# delete without confirmation.
#
# Gate on has_recursive_rm() (flag-position aware) instead of the old whole-
# string regex, so non-recursive `rm -f some-path-with-r` is not caught.
if ! "$needs_token" && has_recursive_rm "$COMMAND"; then
  # Extract path arguments (words that look like paths after the flags)
  # We look for any path under HOME at depth ≥ 2 (contains at least 2 slashes after home root).
  # Build a home-anchored pattern for depth-2+ paths.
  HOME_ESC=""
  if [ -n "${HOME:-}" ]; then
    HOME_ESC=$(printf '%s' "$HOME" | sed 's/[][\/.^$*+?(){}|]/\\&/g')
  fi
  # Match paths like ~/X/Y, $HOME/X/Y, /Users/operator/X/Y — depth ≥ 2 means X/Y exists (two segments).
  DEPTH2_RE="(~|(\\\$HOME)|$HOME_ESC)/[^/[:space:];&|]+/[^[:space:];&|]*"

  if echo "$COMMAND" | grep -qE "$DEPTH2_RE"; then
    # Extract all path-looking tokens and check if any is an excluded safe directory.
    # Safe patterns: node_modules, target, dist, build, .next, .vercel, .cache,
    #   .parcel-cache, .turbo, __pycache__, .pytest_cache, /tmp/, /var/folders/
    SAFE_RE='(node_modules|/target(/|$)|/dist(/|$)|/build(/|$)|\.next(/|$)|\.vercel(/|$)|\.cache(/|$)|\.parcel-cache(/|$)|\.turbo(/|$)|__pycache__|\.pytest_cache|^/tmp/|^/var/folders/)'

    # Collect depth-2+ paths from the command.
    PATHS=$(echo "$COMMAND" | grep -oE "(~|(\\\$HOME)|$HOME_ESC)/[^[:space:];&|]+" || true)

    # Check if all matched paths are safe (excluded). If any is not safe → need token.
    if [ -n "$PATHS" ]; then
      non_safe_found=false
      while IFS= read -r p; do
        if ! echo "$p" | grep -qE "$SAFE_RE"; then
          non_safe_found=true
          break
        fi
      done <<< "$PATHS"
      if "$non_safe_found"; then
        needs_token=true
        trigger="rm -rf at depth≥2 under HOME"
        TRIGGER_CLASS="rm_recursive"
      fi
    fi
  fi
fi

if [ "$needs_token" = false ]; then
  exit 0
fi

# Extract CONFIRM=<token> if present (anywhere in the command).
TOKEN=$(echo "$COMMAND" | grep -oE 'CONFIRM=[a-f0-9]+' | head -1 | cut -d= -f2)

if [ -z "$TOKEN" ]; then
  deny "Blocked: $trigger requires a single-use confirmation token. Operator: run \`claude-confirm\` (or \`claude-confirm $TRIGGER_CLASS\` for a scoped token) in your terminal, paste the token to the agent, then retry the command prefixed with CONFIRM=<token>."
fi

TOKEN_DIR="${CLAUDE_TOKEN_DIR:-$TOKEN_DIR}"

# C5 — prefer a scoped token (<TOKEN>.<TRIGGER_CLASS>) if it exists and is fresh;
# fall back to the exact bare token the operator supplied (legacy path).
TOKEN_FILE_SCOPED="$TOKEN_DIR/${TOKEN}.${TRIGGER_CLASS}"
TOKEN_FILE_BARE="$TOKEN_DIR/$TOKEN"

# Determine which token file to consume: scoped preferred, bare as fallback.
TOKEN_FILE=""
if [ -f "$TOKEN_FILE_SCOPED" ]; then
  TOKEN_FILE="$TOKEN_FILE_SCOPED"
elif [ -f "$TOKEN_FILE_BARE" ]; then
  TOKEN_FILE="$TOKEN_FILE_BARE"
fi

if [ -z "$TOKEN_FILE" ]; then
  deny "Blocked: $trigger — confirmation token '$TOKEN' is unknown or already consumed. Generate a new one with \`claude-confirm\` (or \`claude-confirm $TRIGGER_CLASS\`)."
fi

# TTL check: 60 seconds. Use find with -mmin +1 to detect older-than-1-minute.
if find "$TOKEN_FILE" -mmin +1 2>/dev/null | grep -q .; then
  rm -f "$TOKEN_FILE"
  deny "Blocked: $trigger — confirmation token '$TOKEN' has expired (60s TTL). Generate a new one with \`claude-confirm\`."
fi

# Consume the token atomically — prevents TOCTOU race where two concurrent
# sessions both pass the file-existence check before either deletes it.
# mv fails if the file is already gone (rename is atomic on the same fs).
mv "$TOKEN_FILE" "$TOKEN_DIR/.consumed-$(basename "$TOKEN_FILE")" 2>/dev/null || \
  deny "Blocked: $trigger — confirmation token '$TOKEN' was already consumed (concurrent use). Generate a new one with \`claude-confirm\`."
exit 0
