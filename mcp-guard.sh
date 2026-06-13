#!/bin/bash
# PreToolUse hook — matcher "mcp__.*" — the first BLOCK-capable gate for MCP
# tool calls. Closes red-team 2026-06-07 CRITICAL: MCP calls bypass the entire
# Bash guard stack; the only prior mcp hooks are PostToolUse loggers.
#
# Layers (in order):
#   1.  policy.deny      → hard block (operator opt-in)
#   2.  content sentinel → block payloads that reference a credential path, carry
#       a known secret token, or contain a curl/wget @file exfil shape.
#   2a. control-plane write sentinel (C4) → deny any mcp__ tool whose input
#       references a write to ~/.claude hooks/agents/settings/policy paths, or
#       ~/.claude/skills/*/SKILL.md — closes serena/engraph writing the gate
#       itself or injecting a skill definition.
#   2.5 egress control   → destination-aware gate for network/send-class tools
#       (Cross-Provider Egress Guard). Additive: only tools matching a network
#       mode are gated; everything else falls through unchanged. Fail-closed.
#   3.  policy.require_token → demand a fresh (<60s) claude-confirm token; consume
#       it single-use (atomic mv). With tool-scoped tokens (C5): prefer a token
#       whose suffix matches the current tool-class; bare (legacy) tokens remain a
#       valid fallback. MCP calls have no command channel, so any fresh
#       operator-issued token authorizes the call ("operator confirmed just now").
#   default → allow (PostToolUse loggers still record it).
#
# HARDENED 2026-06-12 (session #1 harness threat-model):
#   F4 (HIGH): the credential-path + curl/wget @file sentinel previously ran ONLY
#     for five hardcoded code-exec/fetch tool NAMES (*ctx_execute*, *browser_*,
#     *ctx_fetch_and_index*). A novel/renamed code-exec MCP tool (mcp__sandbox__
#     run_python, mcp__repl__eval, …) carrying `open('~/.ssh/id_rsa')` slipped it.
#     Reproduced. Fix: the credential-path and @file scans now run UNCONDITIONALLY
#     for every mcp__ tool, exactly like the secret-token scan already did.
#   F5 (MEDIUM): the egress gate's Mode 3 only matched five network NAME globs
#     (fetch/http/send/upload/webhook). A tool named mcp__weird__beacon /
#     __transmit_data shipping a URL fell to default-allow. Reproduced. Fix:
#     Mode 4 — any unknown, non-local, non-connector tool whose payload carries a
#     scheme://host destination is fail-closed.
#   F6 (HIGH): if mcp-gate-policy.json was missing/malformed the hook FAILED OPEN
#     — Layers 1, 2.5 and 3 silently dropped, so every require_token tool (Supabase
#     execute/migrate, GitHub push/merge, Vercel deploy, Cloudflare) became
#     unguarded. Reproduced. Fix: fall back to a built-in require_token list and a
#     built-in default-deny egress posture when the policy can't be read.
#
# HARDENED tournament-11 (blue-team session):
#   C3 (HIGH): ctx_execute/ctx_execute_file and destructive LSP/vault writers
#     (serena__replace_symbol_body, __rename_symbol, __safe_delete_symbol,
#     engraph__delete, __rewrite, __move_note) were not in require_token — any
#     in-session code execution or irreversible symbol/note write was ungated.
#     Fix: added to require_token in policy JSON. Layer 3 here consumes the token.
#   C4 (HIGH): serena/engraph (and any future MCP tool) could write to
#     ~/.claude/hooks/, ~/.claude/agents/, ~/.claude/settings*.json,
#     ~/.claude/mcp-gate-policy.json, ~/.claude.json, ~/.claude/.tokens, or
#     ~/.claude/skills/*/SKILL.md — overwriting the hook itself or injecting a
#     skill backdoor. Fix: Layer 2a scans INPUT_BLOB for these path patterns
#     (same approach as the existing credential-path sentinel) and denies.
#   C5 (MED): confirm tokens were unscoped — any token authorized any high-risk
#     tool call. An attacker who observed a token being issued for (say) a Vercel
#     deploy could replay it for a Supabase execute_sql. Fix: Layer 3 now prefers
#     a tool-class-scoped token file (<hex>.<toolclass>) when one exists, falling
#     back to a bare <hex> legacy token only when no scoped token is present.
#     See the C5 TOOL-SCOPED TOKENS section below for the full design.
#
# NOTE (C5 — no code change): ListMcpResourcesTool and ReadMcpResourceTool are
#   built-in CC tools that use a different matcher type (not "mcp__.*") so they
#   are invisible to this hook. settings.json PreToolUse matcher needs a second
#   entry covering these tool names. This hook cannot fix that; the settings.json
#   owner (operator / def-config) must widen the matcher. Documented here as a
#   known gap; tracking issue: tournament-11 finding C5-note.
#
# Env overrides (for tests; production uses the defaults):
#   MCP_GATE_POLICY   default ~/.claude/mcp-gate-policy.json
#   CLAUDE_TOKEN_DIR  default ~/.claude/.tokens
#
# Register in settings.json hooks.PreToolUse:
#   { "matcher": "mcp__.*",
#     "hooks": [{ "type": "command", "command": "bash ~/.claude/hooks/mcp-guard.sh", "timeout": 5 }] }
set -uo pipefail

POLICY="${MCP_GATE_POLICY:-$HOME/.claude/mcp-gate-policy.json}"
TOKEN_DIR="${CLAUDE_TOKEN_DIR:-$HOME/.claude/.tokens}"

# Secret patterns (best-effort source; fall back to a minimal set).
if ! source "$HOME/.claude/hooks/lib/secret-patterns.sh" 2>/dev/null; then
  SECRET_MEGA_REGEX='AKIA[0-9A-Z]{16}|sk-ant-api[0-9]+-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xox[bpsar]-[A-Za-z0-9-]+'
fi

INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty')
[ -z "$TOOL" ] && exit 0
case "$TOOL" in mcp__*) ;; *) exit 0 ;; esac
INPUT_BLOB=$(printf '%s' "$INPUT" | jq -rc '.tool_input // {}')

. "$HOME/.claude/hooks/lib/deny.sh"

# Glob-match $1 against a newline-separated list of patterns ($2).
match_any() {
  local tool="$1" list="$2" p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    # Skip JSON comment pseudo-entries added for readability in policy file.
    case "$p" in _comment*) continue ;; esac
    # shellcheck disable=SC2254
    case "$tool" in $p) return 0 ;; esac
  done <<< "$list"
  return 1
}

# R6 — emit candidate resource owners from a connector payload ($INPUT_BLOB),
# lowercased + deduped. Reads owner/org/organization/repoOwner (string or
# {login}), the owner part of "owner/repo" in repository / full_name /
# repository_full_name (the field the live GitHub connector actually sends —
# ground-truthed in the victory-lab battery), and any github.com/<owner> URL.
# Each "owner/repo" field is evaluated independently (no // short-circuit), so a
# field that arrives as an object can't shadow a sibling that carries the string.
# A call with no detectable owner emits nothing → passes (the remaining R6
# surface, same class as R3, documented in SECURITY-RESIDUALS).
owners_in_payload() {
  {
    jq -r '
      [ (.owner | if type=="object" then .login else . end),
        .org, .organization, .repoOwner, .repo_owner,
        ((.repository           // "") | if type=="string" and test("/") then split("/")[0] else empty end),
        ((.full_name            // "") | if type=="string" and test("/") then split("/")[0] else empty end),
        ((.repository_full_name // "") | if type=="string" and test("/") then split("/")[0] else empty end)
      ] | map(select(type=="string" and . != "")) | .[]' <<< "$INPUT_BLOB" 2>/dev/null
    printf '%s' "$INPUT_BLOB" | grep -oiE 'github\.com[/:]+[A-Za-z0-9_.-]+' | sed -E 's#.*[/:]##'
  } | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | sort -u
}

# R6 — if $TOOL matches a connector_owner_scope glob, every owner positively
# identified in the payload must be on that glob's allow-list (else deny).
enforce_owner_scope() {
  local g allowed owner
  while IFS= read -r g; do
    [ -z "$g" ] && continue
    # shellcheck disable=SC2254
    case "$TOOL" in $g) ;; *) continue ;; esac
    allowed=$(printf '%s' "$OWNER_SCOPE" | jq -r --arg k "$g" '.[$k][]? // empty' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    while IFS= read -r owner; do
      [ -z "$owner" ] && continue
      if ! printf '%s\n' "$allowed" | grep -qxF "$owner"; then
        deny "Blocked (mcp-guard egress R6): connector $TOOL targets owner '$owner', not on the connector_owner_scope allow-list for '$g'. Scope it to an allowed owner or widen the policy."
      fi
    done <<< "$(owners_in_payload)"
  done <<< "$(printf '%s' "$OWNER_SCOPE" | jq -r 'keys[]?' 2>/dev/null)"
}

DENY_LIST=""; TOKEN_LIST=""
POLICY_OK=false
if [ -f "$POLICY" ] && jq empty "$POLICY" 2>/dev/null; then
  POLICY_OK=true
  DENY_LIST=$(jq -r '.deny[]? // empty' "$POLICY" 2>/dev/null)
  TOKEN_LIST=$(jq -r '.require_token[]? // empty' "$POLICY" 2>/dev/null)
else
  # FAIL-CLOSED (F6): a missing/malformed policy must NOT silently drop the token
  # and egress gates. Fall back to a built-in minimal require_token list and a
  # built-in default-deny egress posture (set further below) until the policy is
  # restored. The always-on content sentinel runs regardless.
  echo "mcp-guard: policy $POLICY missing/invalid — FAILING CLOSED on built-in token + egress defaults" >&2
  TOKEN_LIST='mcp__*Supabase*__execute_sql
mcp__*Supabase*__apply_migration
mcp__*__browser_run_code_unsafe
mcp__*github*__*merge*
mcp__*github*__*push*
mcp__asc-mcp__*submit*
mcp__asc-mcp__*release*
mcp__*Vercel*__*deploy*
mcp__*loudflare*__*
mcp__*ctx_execute*
mcp__*ctx_execute_file*
mcp__serena__replace_symbol_body
mcp__serena__rename_symbol
mcp__serena__safe_delete_symbol
mcp__engraph__delete
mcp__engraph__rewrite
mcp__engraph__move_note'
fi

# ── Layer 1: policy deny ────────────────────────────────────────────────────
if [ -n "$DENY_LIST" ] && match_any "$TOOL" "$DENY_LIST"; then
  deny "Blocked (mcp-guard): $TOOL is on the policy deny list."
fi

# ── Layer 2: always-on content sentinel for ALL mcp tools ───────────────────
# HARDENED F4: the credential-path and curl/wget @file exfil scans no longer
# depend on the tool NAME matching a hardcoded code-exec/fetch pattern — they run
# for every mcp__ tool, the same way the secret-token scan already does. A
# code-exec tool registered under any name can no longer slip a credential path.
HOME_ESC="${HOME//\//\\/}"
SENSITIVE='(\$HOME|~|'"$HOME_ESC"')/(\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.docker/config\.json|\.kube/config|\.netrc|\.pypirc|\.git-credentials|\.anthropic|\.claude/\.tokens)'
if printf '%s' "$INPUT_BLOB" | grep -qE "$SENSITIVE"; then
  deny "Blocked (mcp-guard): $TOOL payload references a protected credential path. MCP tools may not touch ~/.ssh, ~/.aws, etc."
fi
if printf '%s' "$INPUT_BLOB" | grep -qE '(curl|wget)[^"]*([[:space:]=]@[~/.]|-T[[:space:]]+[~/.])'; then
  deny "Blocked (mcp-guard): $TOOL payload contains a curl/wget local-file upload (exfil signature)."
fi
# Any MCP tool shipping a recognizable secret token outward.
if printf '%s' "$INPUT_BLOB" | grep -qE "$SECRET_MEGA_REGEX"; then
  deny "Blocked (mcp-guard): $TOOL input contains a string matching a known secret/token pattern. Refusing to pass a credential to an MCP tool."
fi

# ── Layer 2a: C4 — control-plane write sentinel ──────────────────────────────
# C4 (HIGH): an MCP write tool (serena, engraph, or any future tool) could
# receive a crafted payload targeting the hooks/agents/settings/policy paths that
# constitute the harness itself, or SKILL.md files that inject skill definitions.
# We scan INPUT_BLOB for these path patterns exactly as we scan for credential
# paths above. Note what this sentinel CAN and CANNOT catch:
#   CAN catch: literal path strings in the JSON payload (relative_path, file_path,
#     path, body, code, content, etc.) that mention the protected paths below.
#   CANNOT catch: paths constructed at runtime inside ctx_execute code (e.g. a
#     Python string assembled from variables). That surface is covered by the token
#     gate (Layer 3) — ctx_execute requires a token before any code runs, so the
#     operator has already confirmed the call. The sentinel is defense-in-depth for
#     the static/literal case; the token gate is the real fix for runtime-dynamic
#     code. Both layers are required.
#
# Protected destinations (write-channel to the harness control plane):
#   ~/.claude/hooks/*         — hook scripts themselves
#   ~/.claude/agents/*        — subagent definitions
#   ~/.claude/settings.json   — CC settings (permissions, env, hooks)
#   ~/.claude/settings.local.json
#   ~/.claude/mcp-gate-policy.json — this policy file
#   ~/.claude.json            — CC project-level config
#   ~/.claude/.tokens/*       — confirmation token directory
#   ~/.claude/skills/*/SKILL.md — skill trigger+body definitions (injection point)
CONTROL_PLANE_RE='(\.claude/hooks|\.claude/agents|\.claude/settings(\.local)?\.json|\.claude/mcp-gate-policy\.json|\.claude\.json|\.claude/\.tokens|\.claude/skills/[^/"]*/SKILL\.md)'
if printf '%s' "$INPUT_BLOB" | grep -qE "$CONTROL_PLANE_RE"; then
  deny "Blocked (mcp-guard C4): $TOOL payload references a harness control-plane path (hooks/agents/settings/policy/skills SKILL.md). MCP write tools may not target the gate infrastructure. If this is legitimate operator work, use the native Write/Edit tools with operator oversight."
fi

# ── Layer 2.5: destination-aware egress control ─────────────────────────────
# Additive + fail-closed. Egress params come from policy when valid, else from
# built-in fail-closed defaults (F6). Classification order (first match wins):
#   Mode 1  url_tools          → host(s) extracted from payload must all be allow-listed
#   (skip)  non_egress_servers → localhost/fs-local servers bypass the gate
#   Mode 2  connector_tools    → allow iff full tool name matches an allow_connectors glob
#   Mode 3  network_name_globs → generic network/send name → fail-closed deny
#   Mode 4  unknown + URL      → unknown non-local tool carrying a scheme://host → fail-closed deny (F5)
if $POLICY_OK; then
  EGRESS_DEFAULT=$(jq -r '.egress.default // empty' "$POLICY" 2>/dev/null)
  URL_TOOLS=$(jq -r '.egress.url_tools[]? // empty' "$POLICY" 2>/dev/null)
  ALLOW_HOSTS=$(jq -r '.egress.allow_hosts[]? // empty' "$POLICY" 2>/dev/null)
  CONNECTOR_TOOLS=$(jq -r '.egress.connector_tools[]? // empty' "$POLICY" 2>/dev/null)
  ALLOW_CONNECTORS=$(jq -r '.egress.allow_connectors[]? // empty' "$POLICY" 2>/dev/null)
  NET_GLOBS=$(jq -r '.egress.network_name_globs[]? // empty' "$POLICY" 2>/dev/null)
  OWNER_SCOPE=$(jq -rc '.egress.connector_owner_scope // {}' "$POLICY" 2>/dev/null)
  MAXBYTES=$(jq -r '.egress.max_payload_bytes_to_novel_host // 512' "$POLICY" 2>/dev/null)
  NON_EGRESS=$(jq -r '.egress.non_egress_servers[]? // empty' "$POLICY" 2>/dev/null)
else
  EGRESS_DEFAULT=deny
  URL_TOOLS=''
  ALLOW_HOSTS=''
  CONNECTOR_TOOLS=''
  ALLOW_CONNECTORS=''
  NET_GLOBS=$'mcp__*fetch*\nmcp__*http*\nmcp__*send*\nmcp__*upload*\nmcp__*webhook*'
  OWNER_SCOPE='{}'
  MAXBYTES=512
  NON_EGRESS=$'bridge-db\nserena\nengraph\ncost-tracker\nportfolio-health\npersonal_ops\nplugin_context-mode_context-mode'
fi

if [ "$EGRESS_DEFAULT" = "deny" ]; then
  # non_egress_servers match the EXACT server segment of mcp__<server>__<tool>,
  # not a prefix glob — so "bridge-db" can never shadow "bridge-db-hosted".
  SERVER="${TOOL#mcp__}"; SERVER="${SERVER%%__*}"
  is_non_egress=false
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    if [ "$SERVER" = "$s" ]; then is_non_egress=true; break; fi
  done <<< "$NON_EGRESS"

  if match_any "$TOOL" "$URL_TOOLS"; then
    # Mode 1 — extract every host from the payload; all must be allow-listed.
    HOSTS=$(printf '%s' "$INPUT_BLOB" | grep -oiE '[a-z][a-z0-9+.-]*://[^/?#"'"'"' ]+' \
            | sed -E 's#^[a-z][a-z0-9+.-]*://##; s#^.*@##; s#:.*$##; s#\.$##' \
            | tr '[:upper:]' '[:lower:]' | sort -u)
    if [ -z "$HOSTS" ]; then
      deny "Blocked (mcp-guard egress): $TOOL is a URL-class tool but no destination host could be extracted from its input. Fail-closed."
    fi
    PAYLOAD_BYTES=${#INPUT_BLOB}
    while IFS= read -r h; do
      [ -z "$h" ] && continue
      host="${h%%:*}"   # strip :port
      if ! match_any "$host" "$ALLOW_HOSTS"; then
        if [ "$PAYLOAD_BYTES" -gt "$MAXBYTES" ]; then
          deny "Blocked (mcp-guard egress): $TOOL targets non-allowlisted host '$host' with an oversized payload (${PAYLOAD_BYTES}B > ${MAXBYTES}B). Fail-closed."
        fi
        deny "Blocked (mcp-guard egress): $TOOL targets non-allowlisted host '$host'. Add it to egress.allow_hosts or use an allowed destination."
      fi
    done <<< "$HOSTS"
    # all hosts allow-listed → fall through (allow)
  elif $is_non_egress; then
    : # local / non-egress server — no destination control
  elif match_any "$TOOL" "$CONNECTOR_TOOLS"; then
    # Mode 2 — fixed-backend connector; must be on the allow_connectors list.
    if ! match_any "$TOOL" "$ALLOW_CONNECTORS"; then
      deny "Blocked (mcp-guard egress): connector $TOOL is not on the egress allow_connectors list (unknown/renamed connector). Fail-closed."
    fi
    enforce_owner_scope   # R6 — connector resource (owner) scoping
  elif match_any "$TOOL" "$NET_GLOBS"; then
    # Mode 3 — generic network/send name from a non-local, non-connector server.
    deny "Blocked (mcp-guard egress): $TOOL matches a network/send-class name but its destination cannot be verified (Mode 3 fail-closed catch-all)."
  elif printf '%s' "$INPUT_BLOB" | grep -qiE '[a-z][a-z0-9+.-]*://[a-z0-9._-]+'; then
    # Mode 4 (F5) — unknown, non-local, non-connector tool whose NAME matched no
    # network glob but whose payload carries a scheme://host destination. A novel
    # exfil tool (beacon/transmit/relay/emit/…) lands here → fail-closed.
    deny "Blocked (mcp-guard egress): $TOOL is an unrecognized non-local tool carrying a URL destination in its payload (Mode 4 fail-closed). If this is a legitimate local tool, add its server to egress.non_egress_servers; if a known connector, add it to connector_tools/allow_connectors."
  fi
fi

# ── Layer 3: require a fresh confirm token for high-risk tools ───────────────
# C5 — TOOL-SCOPED TOKENS
#
# Design: a token file may be named either:
#   <hex>           — legacy bare token, authorizes any require_token tool
#   <hex>.<toolclass> — scoped token, only authorizes tools matching <toolclass>
#
# <toolclass> is a short string the operator's `claude-confirm` issuer appends
# when the operator knows which tool class they are authorizing (e.g.
# `claude-confirm ctx_execute` emits a token file named `<hex>.ctx_execute`).
# The issuer side of this protocol is NOT in scope here — this file implements
# the VALIDATOR side only.
#
# Precedence: when a scoped token exists whose suffix matches the current tool
# class, it is preferred and consumed. A bare legacy token is consumed ONLY when
# no matching scoped token is found. This means:
#   - Operators using the old unscoped `claude-confirm` continue to work (backward
#     compat — no break in existing workflow).
#   - Once a scoped token is issued, it cannot be replayed for a different class.
#
# TRADEOFF documented: bare tokens remain a fallback. This means a bare token
# issued before C5 is hardened fully still authorizes any require_token class.
# The forward path is to update `claude-confirm` to emit scoped tokens by default
# and eventually remove the bare fallback — but that is an issuer-side change and
# must not break operators who haven't updated. The validator accepting bare tokens
# as a fallback is the safe migration path.
#
# Tool-class derivation: the last __ segment of the tool name is the "op" (e.g.
# mcp__serena__replace_symbol_body → replace_symbol_body). We map ops to a short
# class name so the token scope stays predictable across renamed/versioned tools:
#   ctx_execute* → ctx_execute
#   ctx_execute_file* → ctx_execute
#   replace_symbol_body / rename_symbol / safe_delete_symbol → serena_write
#   engraph__delete / engraph__rewrite / engraph__move_note → engraph_write
#   Supabase execute_sql / apply_migration / *delete* / *drop* → supabase_write
#   github *merge* / *push* / *delete* → github_write
#   Vercel *deploy* → vercel_deploy
#   Cloudflare * → cloudflare_write
#   browser_run_code_unsafe → browser_exec
#   asc-mcp *submit* / *release* → asc_release
#   bridge-db clear_handoff / mark_shipped_processed → bridge_write
#   (everything else) → generic
#
# The test harness and `claude-confirm` issuer must use these same class strings.

# Derive tool-class from $TOOL.
tool_class() {
  local t="$1"
  local op="${t##*__}"   # last __ segment
  case "$t" in
    *ctx_execute_file*)        echo "ctx_execute" ;;
    *ctx_execute*)             echo "ctx_execute" ;;
    *replace_symbol_body*|*rename_symbol*|*safe_delete_symbol*)
                               echo "serena_write" ;;
    *engraph__delete*|*engraph__rewrite*|*engraph__move_note*)
                               echo "engraph_write" ;;
    *Supabase*execute_sql*|*Supabase*apply_migration*|*Supabase**delete*|*Supabase**drop*)
                               echo "supabase_write" ;;
    *github**merge*|*github**push*|*github**delete*)
                               echo "github_write" ;;
    *Vercel**deploy*)          echo "vercel_deploy" ;;
    *loudflare*)               echo "cloudflare_write" ;;
    *browser_run_code_unsafe*) echo "browser_exec" ;;
    *asc-mcp**submit*|*asc-mcp**release*)
                               echo "asc_release" ;;
    *bridge-db__clear_handoff*|*bridge-db__mark_shipped_processed*)
                               echo "bridge_write" ;;
    *)                         echo "generic" ;;
  esac
}

if [ -n "$TOKEN_LIST" ] && match_any "$TOOL" "$TOKEN_LIST"; then
  CLASS=$(tool_class "$TOOL")

  # C5: prefer a scoped token (<hex>.<class>) if one exists and is fresh (<60s).
  # Fall back to a bare legacy token if no scoped token is found.
  FRESH=""
  if [ -d "$TOKEN_DIR" ]; then
    # Try scoped token first.
    FRESH=$(find "$TOKEN_DIR" -maxdepth 1 -type f \
              -name "[0-9a-f]*.$CLASS" ! -name '.consumed-*' -mmin -1 2>/dev/null \
            | head -1 || true)
    # Fall back to bare (legacy) token.
    if [ -z "$FRESH" ]; then
      FRESH=$(find "$TOKEN_DIR" -maxdepth 1 -type f \
                -name '[0-9a-f]*' ! -name '[0-9a-f]*.*' ! -name '.consumed-*' -mmin -1 2>/dev/null \
              | head -1 || true)
    fi
  fi

  if [ -z "$FRESH" ]; then
    deny "Blocked (mcp-guard): $TOOL is high-risk (class: $CLASS) and requires operator confirmation. Operator: run \`claude-confirm\` (or \`claude-confirm $CLASS\` for a scoped token) in your terminal within 60s, then have the agent retry this MCP call."
  fi
  # Single-use atomic consume (TOCTOU-safe).
  mv "$FRESH" "$TOKEN_DIR/.consumed-$(basename "$FRESH")" 2>/dev/null \
    || deny "Blocked (mcp-guard): confirmation token was already consumed (concurrent use). Generate a new one with \`claude-confirm\`."
fi

exit 0
