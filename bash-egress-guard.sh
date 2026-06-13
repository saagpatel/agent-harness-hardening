#!/bin/bash
# PreToolUse hook — matcher "Bash" — destination-aware egress control for shell
# network commands (curl/wget/scp/rsync/nc/...). Closes residual R5: mcp-guard.sh
# gates mcp__* only, so CC's Bash lane had no destination check while Codex's
# common.py did. This gives the CC shell lane the SAME Mode-1 host allow-listing,
# reading the SAME canonical ~/.claude/mcp-gate-policy.json `.egress.allow_hosts`.
# Parity sibling of Codex egress_shell_decision(). Additive + fail-closed.
#
# Behavior: only fires on shell network verbs; non-network Bash commands pass
# untouched. A network command to a non-allowlisted host is denied; loopback is
# allowed (not external egress). Like Codex, host verification needs a
# scheme-qualified URL / scp `user@host:` / `nc host port` — a network command with
# no extractable host fails closed (use http://localhost:PORT, not bare host:port).
#
# Env override (tests): MCP_GATE_POLICY (default ~/.claude/mcp-gate-policy.json)
#
# Register in settings.json hooks.PreToolUse under the existing "Bash" matcher:
#   bash ~/.claude/hooks/bash-egress-guard.sh
#
# HARDENED tournament-11:
#   R2-G-A (HIGH)  — download-then-exec via allowed host
#   R2-G-C (HIGH)  — /dev/tcp|udp + DNS egress (dig/nslookup/host/drill/socat)
#   R2-G-D (MED)   — pipe to unknown interpreter (open-world deny)
#   R2-G-E (HIGH)  — raw curl/wget mutating write to api.github.com
#   R4-Q   (HIGH)  — length gate prevents timeout→fail-open
#
# RESIDUAL LIMITS (non-network exfil sinks, out of egress scope today):
#   • open https://… — launches browser, data visible in URL; low severity but not gated here
#   • pbcopy — copies to clipboard; no network egress; OS-level scope
#   • osascript Mail — app-layer send path; not a shell network verb
#   • iCloud/Drive sync dirs — filesystem write, sync is OS-level; not catchable here
#   The download-then-exec heuristic (R2-G-A) cannot catch arbitrarily-obfuscated
#   multi-step chains where the fetch and exec span separate Bash invocations, or
#   where the exec path is derived programmatically at runtime. Defense-in-depth via
#   the per-host allow-list remains the primary control for those cases.

set -uo pipefail

POLICY="${MCP_GATE_POLICY:-$HOME/.claude/mcp-gate-policy.json}"

INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty')
[ "$TOOL" = "Bash" ] || exit 0
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')

. "$HOME/.claude/hooks/lib/deny.sh"

# ── R4-Q: length gate — prevents regex timeout → fail-open ──────────────────
# A command over 512 KiB is implausible for legitimate work and is a reliable
# signal for a prompt-injection payload designed to exhaust the hook timeout.
# Fail closed (deny) rather than pass-through.
# [R4-Q]
if [ "${#CMD}" -gt 524288 ]; then
  deny "Blocked (bash-egress R4-Q): command length ${#CMD} exceeds 524288-byte safety limit. Split into smaller commands."
fi

# Shared helpers used by BOTH the git/gh owner+host scope (R12/R13, runs first) and
# the network-verb host gate (below). Defined up here so they exist when the git/gh
# enforcement fires — the network section runs strictly later.
LOOPBACK='localhost 127.0.0.1 0.0.0.0 ::1 [::1]'
emit_norm_host() {
  # normalize one [user@]host[:port] (or IPv6 literal) and emit it lowercased
  local h="${1##*@}"
  case "$h" in \[*\]*) h="${h%%\]*}]" ;; *) h="${h%%/*}"; h="${h%%:*}" ;; esac
  h="${h%.}"
  [ -n "$h" ] && printf '%s\n' "$h" | tr '[:upper:]' '[:lower:]'
}

# Policy load — shared by the R12 git/gh owner-scope and the network-host gate
# (egress active = default deny + readable). ALLOW_HOSTS feeds the host gate;
# the presence of github_shell_owners arms the git/gh owner-scope (additive/opt-in).
POLICY_OK=false; ALLOW_HOSTS=''
if [ -f "$POLICY" ] && jq -e '.egress.default == "deny"' "$POLICY" >/dev/null 2>&1; then
  POLICY_OK=true
  ALLOW_HOSTS=$(jq -r '.egress.allow_hosts[]? // empty' "$POLICY" 2>/dev/null)
fi
GH_SCOPE_ACTIVE=false; GH_OWNERS=''
if $POLICY_OK && jq -e '.egress | has("github_shell_owners")' "$POLICY" >/dev/null 2>&1; then
  GH_SCOPE_ACTIVE=true
  GH_OWNERS=$(jq -r '.egress.github_shell_owners[]? // empty' "$POLICY" 2>/dev/null | tr '[:upper:]' '[:lower:]')
fi
# R13: write-destination host allow-list (armed only when github_shell_hosts present,
# additive/opt-in — same model as github_shell_owners).
GH_HOSTS_ACTIVE=false; GH_HOSTS=''
if $POLICY_OK && jq -e '.egress | has("github_shell_hosts")' "$POLICY" >/dev/null 2>&1; then
  GH_HOSTS_ACTIVE=true
  GH_HOSTS=$(jq -r '.egress.github_shell_hosts[]? // empty' "$POLICY" 2>/dev/null | tr '[:upper:]' '[:lower:]')
fi

# ── R12: git/gh shell GitHub owner-scope (writes-only) ──────────────────────
# The agent's real GitHub lane is `git`/`gh`, which the network-verb gate below
# does NOT cover (git/gh are not network verbs; git-over-ssh is untouched). Owner-
# scope applies ONLY to write-class (exfil-OUT) operations: `git push` (+ remote
# add/set-url, which configures a push destination) and `gh` mutating subcommands.
# READS to any owner are allowed (clone/fetch/pull/ls-remote, gh view/list/clone,
# gh api GET) — read data stays local and cannot leave without hitting an already-
# gated send path, so gating reads buys little and blocks normal dev (third-party
# clones, dependency pulls, research). A positively-identified disallowed owner on
# a write denies; an undeterminable owner passes (R3-class). Non-egress git/gh
# subcommands (commit/log/status…) are never scanned, so a GitHub URL in a commit
# message is ignored. gh verbs not on GH_READ_VERBS are treated as writes (fail-
# closed); gh api is a read only when it is a plain GET. Parity sibling of Codex
# _egress_git_gh_owners. Non-github hosts are out of scope (documented residual).
GH_READ_VERBS=' view list clone status diff checkout download browse search ls get cat read show '
GG_SEP=' ; && || | & ( ) '

# Quote-aware tokenizer (no eval — a hand char-scanner, so command substitutions
# are never executed): one token per line; quoted strings collapse to a single
# token (quotes stripped, contents kept); shell operators become their own tokens
# so command positions can be tracked. This is what prevents the commit-message
# false-positive: `git commit -m "git push github.com/x"` tokenizes the message as
# ONE arg of `commit` (a non-egress subcommand) — never a command word.
gg_tokenize() {
  local s="$1"; local i=0 n=${#s} c q='' cur='' have=0
  while [ "$i" -lt "$n" ]; do
    c="${s:$i:1}"
    if [ -n "$q" ]; then
      if [ "$c" = "$q" ]; then q=''; else cur+="$c"; have=1; fi
    else
      case "$c" in
        \'|\")   q="$c"; have=1 ;;
        ' '|"	"|$'\n') [ "$have" = 1 ] && printf '%s\n' "$cur"; cur=''; have=0 ;;
        ';'|'('|')') [ "$have" = 1 ] && printf '%s\n' "$cur"; cur=''; have=0; printf '%s\n' "$c" ;;
        '&') [ "$have" = 1 ] && printf '%s\n' "$cur"; cur=''; have=0
             if [ "${s:$((i+1)):1}" = '&' ]; then printf '&&\n'; i=$((i+1)); else printf '&\n'; fi ;;
        '|') [ "$have" = 1 ] && printf '%s\n' "$cur"; cur=''; have=0
             if [ "${s:$((i+1)):1}" = '|' ]; then printf '||\n'; i=$((i+1)); else printf '|\n'; fi ;;
        *)   cur+="$c"; have=1 ;;
      esac
    fi
    i=$((i+1))
  done
  [ "$have" = 1 ] && printf '%s\n' "$cur"
}

# Emit the lowercased owner if $1 is a github.com URL/spec (https / ssh / scp form).
# Input is lowercased FIRST so the match is case-insensitive (parity with Codex's
# re.IGNORECASE) — else `https://GITHUB.COM/attacker/x` would evade the gate.
gg_emit_url_owner() {
  local a owner
  a=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  # `github.com.?` tolerates the FQDN trailing dot (github.com./owner resolves to real
  # github but would otherwise evade owner extraction). The host suffix attack
  # (github.com.evil.com/…) does NOT match — there `github.com` is followed by `.evil`,
  # not a path separator — and is denied by the R13 host gate instead.
  case "$a" in
    *github.com[/:]*|*github.com.[/:]*)
      owner=$(printf '%s' "$a" | sed -E 's#^.*github\.com\.?[/:]+##; s#[/:].*$##')
      [ -n "$owner" ] && { printf 'O\t%s\n' "$owner"; return 0; } ;;
  esac
  return 1
}
# Emit the owner of an `owner/repo` (or `repos/owner/repo`, or github URL) spec.
gg_emit_ownerrepo() {
  local s owner
  s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$s" in *github.com[/:]*) gg_emit_url_owner "$s"; return ;; esac
  s="${s#/}"; s="${s#repos/}"
  owner="${s%%/*}"
  case "$owner" in ''|-*) return ;; esac
  printf 'O\t%s\n' "$owner"
}
# R13 — emit the normalized destination HOST of a git write URL/scp-spec (tagged H),
# or nothing if no host is determinable (bare remote → resolved separately). Reuses
# emit_norm_host so userinfo (github.com@evil → evil.tld), trailing dot (github.com.
# → github.com), and ports resolve to the TRUE host. Deceptive forms (homoglyph,
# github.com.evil.com suffix, userinfo-spoof, IP-literal, punycode) therefore land on
# their real host and fail the github_shell_hosts allow-list. Only scheme URLs and
# user@host:scp-form carry a host here (a bare host:path or refspec emits nothing —
# R3-class), so refspecs like HEAD:main / v1.0:main are never mistaken for a host.
gg_emit_dest_host() {
  local t="$1" auth h
  case "$t" in
    *://*) auth="${t#*://}"; auth="${auth%%/*}"; auth="${auth%%\?*}"; auth="${auth%%#*}"
           h=$(emit_norm_host "$auth") ;;
    *@*:*) h=$(emit_norm_host "${t%%:*}") ;;
    *) return ;;
  esac
  [ -n "$h" ] && printf 'H\t%s\n' "$h"
}
# Resolve a bare git remote name to an owner via the cwd's config (best-effort;
# unreadable / not-a-repo / no-such-remote → emits nothing → passes, R3-class).
# 2s timeout (parity with Codex) so a slow/NFS .git/config can't hang the hook;
# falls back to plain git where `timeout` isn't installed (e.g. stock macOS).
gg_resolve_remote() {
  local rem="$1" url
  [ -n "$CWD" ] || return
  if command -v timeout >/dev/null 2>&1; then
    url=$(timeout 2 git -C "$CWD" remote get-url "$rem" 2>/dev/null) || return
  else
    url=$(git -C "$CWD" remote get-url "$rem" 2>/dev/null) || return
  fi
  gg_emit_url_owner "$url"
  gg_emit_dest_host "$url"
}
gg_is_sep() { case "$GG_SEP" in *" $1 "*) return 0 ;; esac; return 1; }

# Walk a git invocation at token index $1; emit owners of WRITE-class destinations
# only — push (exfil-out) and remote add/set-url (configures a push destination).
# Reads (clone/fetch/pull/ls-remote/submodule) emit nothing → allowed to any owner.
gg_scan_git() {
  local j="$1" sub='' a; local -a args=()
  j=$((j+1))                                   # skip the `git` word
  while [ "$j" -lt "$n" ]; do                  # skip pre-subcommand global flags
    a="${toks[$j]}"; gg_is_sep "$a" && return
    case "$a" in
      -C|-c|--git-dir|--work-tree|--namespace|--exec-path) j=$((j+2)); continue ;;
      -*) j=$((j+1)); continue ;;
      *) sub="$a"; j=$((j+1)); break ;;
    esac
  done
  case "$sub" in push|remote) ;; *) return ;; esac   # write-class only
  while [ "$j" -lt "$n" ]; do                   # collect this segment's args
    a="${toks[$j]}"; gg_is_sep "$a" && break
    args+=("$a"); j=$((j+1))
  done
  for a in "${args[@]}"; do gg_emit_url_owner "$a"; done   # owners (O) from explicit github URLs
  if [ "$sub" = push ]; then
    local dest=''                                # destination = first non-flag arg (rest are refspecs)
    for a in "${args[@]}"; do case "$a" in -*) continue ;; *) dest="$a"; break ;; esac; done
    [ -z "$dest" ] && dest=origin
    case "$dest" in
      *://*|*@*:*) gg_emit_dest_host "$dest" ;;   # R13 host (H) from the explicit destination
      *) gg_resolve_remote "$dest" ;;             # bare remote → O+H via cwd config (R3 if unresolvable)
    esac
  else                                            # remote: host-gate add/set-url destination URLs (R13)
    case "${args[0]:-}" in
      add|set-url) for a in "${args[@]}"; do case "$a" in *://*|*@*:*) gg_emit_dest_host "$a" ;; esac; done ;;
    esac
  fi
}
# True if a `gh api` invocation mutates: a non-GET method or a request body field.
# `[ =]*` (not `+`) catches the bundled `-XPOST` form; trailing-space-free `-[fF]`
# catches bundled `-ftitle=…` — both are valid gh and both imply a write.
gg_gh_api_is_write() {
  printf '%s' " $* " | grep -qiE '(-X|--method)[ =]*(POST|PUT|PATCH|DELETE)|--field|--raw-field|--input|[[:space:]]-[fF]'
}
# Walk a gh invocation at token index $1; emit owners of WRITE-class targets only.
# Reads (verb on GH_READ_VERBS, gh api GET, search/browse/auth/config/...) emit
# nothing → allowed to any owner. Unknown verbs default to write (fail-closed).
gg_scan_gh() {
  local j="$1" sub='' verb='' a; local -a args=()
  j=$((j+1))                                   # skip the `gh` word
  while [ "$j" -lt "$n" ]; do
    a="${toks[$j]}"; gg_is_sep "$a" && return
    case "$a" in -*) j=$((j+1)); continue ;; *) sub="$a"; j=$((j+1)); break ;; esac
  done
  [ -z "$sub" ] && return
  while [ "$j" -lt "$n" ]; do
    a="${toks[$j]}"; gg_is_sep "$a" && break
    args+=("$a"); j=$((j+1))
  done
  local is_write=1
  case "$sub" in
    search|browse|status|auth|config|alias|extension|help|version|completion) is_write=0 ;;
    api) gg_gh_api_is_write "${args[@]}" || is_write=0 ;;
    *)
      for a in "${args[@]}"; do case "$a" in -*) continue ;; *) verb="$a"; break ;; esac; done
      case "$GH_READ_VERBS" in *" $verb "*) is_write=0 ;; esac ;;
  esac
  [ "$is_write" = 0 ] && return                  # read → allowed to any owner
  # R13: gh's default backend (the GitHub host) is already covered by R12 owner-scope,
  # so it needs no host literal here; only an explicit --hostname (gh api enterprise
  # host) is host-gated. NOT -H: that is --head (a branch) on `gh pr create` and
  # --header on `gh api`, never a hostname — matching it would falsely deny legit ops.
  local ghhost='' hk=0 hm=${#args[@]}
  while [ "$hk" -lt "$hm" ]; do
    case "${args[$hk]}" in
      --hostname) hk=$((hk+1)); [ "$hk" -lt "$hm" ] && ghhost=$(printf '%s' "${args[$hk]}" | tr '[:upper:]' '[:lower:]') ;;
      --hostname=*) ghhost=$(printf '%s' "${args[$hk]#--hostname=}" | tr '[:upper:]' '[:lower:]') ;;
    esac
    hk=$((hk+1))
  done
  [ -n "$ghhost" ] && printf 'H\t%s\n' "$ghhost"
  local k=0 m=${#args[@]}
  while [ "$k" -lt "$m" ]; do
    a="${args[$k]}"
    case "$a" in
      --repo|-R) k=$((k+1)); [ "$k" -lt "$m" ] && gg_emit_ownerrepo "${args[$k]}" ;;
      --repo=*) gg_emit_ownerrepo "${a#--repo=}" ;;
      *github.com[/:]*) gg_emit_url_owner "$a" ;;
      repos/*|/repos/*) gg_emit_ownerrepo "$a" ;;
      -*) ;;                                     # other flags carry no owner
      */*) [ "$sub" = repo ] && gg_emit_ownerrepo "$a" ;;
    esac
    k=$((k+1))
  done
}
# All WRITE-class git/gh egress TARGETS in $CMD, tagged + deduped: `O<TAB>owner`
# (R12 owner-scope) and `H<TAB>host` (R13 write-host allow-list).
gg_github_targets() {
  local -a toks=(); local t; local n
  while IFS= read -r t; do toks+=("$t"); done < <(gg_tokenize "$CMD")
  n=${#toks[@]}; local i=0 cmdpos=1
  while [ "$i" -lt "$n" ]; do
    t="${toks[$i]}"
    if gg_is_sep "$t"; then cmdpos=1; i=$((i+1)); continue; fi
    if [ "$cmdpos" = 1 ]; then
      case "$t" in
        [A-Za-z_]*=*) i=$((i+1)); continue ;;                       # env assignment
        env|time|sudo|nohup|nice|command|builtin|exec|xargs|then|do|else) i=$((i+1)); continue ;;
      esac
      cmdpos=0
      case "$t" in
        git|*/git) gg_scan_git "$i" ;;
        gh|*/gh)   gg_scan_gh  "$i" ;;
      esac
    fi
    i=$((i+1))
  done
}
# Exact-match (+ loopback) check for an R13 write-destination host.
gh_host_allowed() {
  local h="$1" g
  for g in $LOOPBACK; do [ "$h" = "$g" ] && return 0; done
  while IFS= read -r g; do [ -z "$g" ] && continue; [ "$h" = "$g" ] && return 0; done <<< "$GH_HOSTS"
  return 1
}
# R12 + R13 enforcement: deny a WRITE to a non-allow-listed owner (R12, tag O) or a
# non-allow-listed destination host (R13, tag H). Each gate fires only when armed.
enforce_github_shell_scope() {
  $GH_SCOPE_ACTIVE || $GH_HOSTS_ACTIVE || return 0
  local tag val
  while IFS=$'\t' read -r tag val; do
    [ -z "$val" ] && continue
    case "$tag" in
      O) $GH_SCOPE_ACTIVE || continue
         printf '%s\n' "$GH_OWNERS" | grep -qxF "$val" || \
           deny "Blocked (bash-egress R12): git/gh command targets GitHub owner '$val', not on egress.github_shell_owners. Use an allow-listed owner or widen the policy." ;;
      H) $GH_HOSTS_ACTIVE || continue
         gh_host_allowed "$val" || \
           deny "Blocked (bash-egress R13): git/gh write targets host '$val', not on egress.github_shell_hosts. Use an allow-listed host or widen the policy." ;;
    esac
  done <<< "$(gg_github_targets | sort -u)"
}
# Cheap pre-filter: only tokenize/walk when git or gh actually appears.
if printf '%s' "$CMD" | grep -qiE '\b(git|gh)\b'; then enforce_github_shell_scope; fi

# ── R2-G-D: pipe-to-unknown-interpreter (open-world deny) ───────────────────
# Replace the closed enumeration of shell names with an open-world check:
# deny `(curl|wget) … | <X>` where <X> is NOT on the safe-filter allowlist.
# Safe filters: pure data-transform tools with no execution capability.
# [R2-G-D]
SAFE_PIPE_FILTERS=' grep jq awk sed sort uniq head tail tee cat wc tr cut '
if printf '%s' "$CMD" | grep -qiE '\b(curl|wget)\b'; then
  # Extract what follows a pipe after a curl/wget command.
  # Pattern: look for `| <word>` following curl/wget on the same logical line.
  PIPE_DEST=$(printf '%s' "$CMD" | grep -oiE '\b(curl|wget)\b[^|]*\|[[:space:]]*[A-Za-z0-9_/.-]+' \
              | sed -E 's/.*\|[[:space:]]*//' | tr '[:upper:]' '[:lower:]' | grep -oE '^[A-Za-z0-9_/.-]+')
  while IFS= read -r pd; do
    [ -z "$pd" ] && continue
    # Normalize: strip path prefix for allowlist check
    pbase=$(basename "$pd")
    case "$SAFE_PIPE_FILTERS" in
      *" $pbase "*) ;;   # safe data-transform filter — allow
      *)
        deny "Blocked (bash-egress R2-G-D): curl/wget piped to '$pd' which is not on the safe-filter allowlist. Pipe to a data-transform tool (grep/jq/awk/sed/…) or download first and inspect." ;;
    esac
  done <<< "$PIPE_DEST"
fi

# ── R2-G-E: raw curl/wget mutating write to api.github.com ──────────────────
# Detect `(curl|wget)` to api.github.com with a mutating method or request body.
# This closes the exfil-via-allowed-host hole: an agent can't use curl to create
# gists, push code, or exfiltrate data via the GitHub API even if api.github.com
# is on the allow-list. GET requests are allowed (read-only, no exfil).
# [R2-G-E]
if printf '%s' "$CMD" | grep -qiE '\b(curl|wget)\b.*api\.github\.com'; then
  # Check for mutating method or request-body flags
  if printf '%s' "$CMD" | grep -qiE '\b(curl|wget)\b.*api\.github\.com.*(-X[[:space:]]*(POST|PUT|PATCH|DELETE)|--request[[:space:]]*(POST|PUT|PATCH|DELETE)|--data(-[a-z]+)?[[:space:]]|-d[[:space:]]|-F[[:space:]]|-T[[:space:]]|--upload-file[[:space:]])' || \
     printf '%s' "$CMD" | grep -qiE '\b(curl|wget)\b.*(-X[[:space:]]*(POST|PUT|PATCH|DELETE)|--request[[:space:]]*(POST|PUT|PATCH|DELETE)|--data(-[a-z]+)?[[:space:]]|-d[[:space:]]|-F[[:space:]]|-T[[:space:]]|--upload-file[[:space:]]).*api\.github\.com'; then
    deny "Blocked (bash-egress R2-G-E): curl/wget with a mutating method (POST/PUT/PATCH/DELETE) or request body targeting api.github.com is not permitted. Use the 'gh' CLI for GitHub API writes, which is subject to the owner-scope gate."
  fi
fi

# ── R2-G-C: /dev/tcp|udp egress + DNS exfil channels ───────────────────────
# /dev/tcp/<host>/<port> is a bash built-in that opens a raw TCP socket, bypassing
# the network-verb pre-filter entirely. Extract the host and run it through the
# allow-list. Also adds DNS/socket exfil tools (dig/nslookup/host/drill/socat) to
# the network-verb surface so they reach the host gate.
#
# NOTE: host_allowed() is defined after the verb gate below (it depends on ALLOW_HOSTS
# being loaded). We use an early_host_allowed() here that duplicates the same logic
# with the already-loaded ALLOW_HOSTS and LOOPBACK globals — no forward-reference risk.
# [R2-G-C]
early_host_allowed() {
  local h="$1" g
  for g in $LOOPBACK; do [ "$h" = "$g" ] && return 0; done
  while IFS= read -r g; do
    [ -z "$g" ] && continue
    # shellcheck disable=SC2254
    case "$h" in $g) return 0 ;; esac
  done <<< "$ALLOW_HOSTS"
  return 1
}
if printf '%s' "$CMD" | grep -qE '/dev/(tcp|udp)/'; then
  # Policy must be active for /dev/tcp — fail closed if not.
  $POLICY_OK || deny "Blocked (bash-egress R2-G-C): /dev/tcp|udp detected and egress policy unavailable (fail-closed)."
  # Extract host from /dev/tcp/<host>/<port> or /dev/udp/<host>/<port>.
  # BSD sed doesn't support \2 backreferences in ERE (-E); strip prefix/suffix with
  # two sequential sed passes (portable across macOS and Linux).
  DEVTCP_HOSTS=$(printf '%s' "$CMD" | grep -oE '/dev/(tcp|udp)/[^/[:space:]]+/[0-9]+' \
                 | sed 's|/dev/tcp/||; s|/dev/udp/||' \
                 | sed 's|/[0-9]*$||' \
                 | tr '[:upper:]' '[:lower:]')
  # If no host could be extracted, fail closed
  if [ -z "$DEVTCP_HOSTS" ]; then
    deny "Blocked (bash-egress R2-G-C): /dev/tcp|udp with no extractable host (fail-closed)."
  fi
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    early_host_allowed "$h" || \
      deny "Blocked (bash-egress R2-G-C): /dev/tcp|udp connection to non-allowlisted host '$h'. Add it to egress.allow_hosts or use an allowed destination."
  done <<< "$DEVTCP_HOSTS"
fi

# ── Network-verb gate — only shell network commands reach the host check below ─
# R2-G-C: added dig, nslookup, host, drill, socat to catch DNS/socket exfil channels.
# [R2-G-C]
printf '%s' "$CMD" | grep -qiE '\b(curl|wget|scp|rsync|ncat|telnet|sftp|ftp|ssh|dig|nslookup|drill|socat)\b|(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)|\bhost\b' || exit 0

# Network commands need an active policy, else fail closed.
$POLICY_OK || deny "Blocked (bash-egress): egress policy unavailable; refusing network shell command (fail-closed)."

host_allowed() {
  local h="$1" g
  for g in $LOOPBACK; do [ "$h" = "$g" ] && return 0; done
  while IFS= read -r g; do
    [ -z "$g" ] && continue
    # shellcheck disable=SC2254
    case "$h" in $g) return 0 ;; esac
  done <<< "$ALLOW_HOSTS"
  return 1
}

# ssh destination extraction (R10) — parity with Codex _egress_ssh_hosts.
# Flag-aware: skip option flags + the value tokens of value-taking flags, so the
# first BARE token after `ssh` (ssh's own destination rule) is the host. ssh://
# URIs are handled by URL_HOSTS, not here. Any mis-parse lands on a flag value or
# the remote command (non-allowlisted -> deny) or yields nothing (fail-closed).
# git-over-ssh has no literal `ssh` token and is untouched.
SSH_VALUE_FLAGS=' B b c D E e F I i J L l m O o p Q R S W w '   # OpenSSH value-taking opts
# (emit_norm_host is defined near the top — shared with the R12/R13 git/gh scope.)
# Jump hosts (-J / -o ProxyJump=) are DIRECT local egress — the client connects to
# each jump before the target — so they MUST be extracted, unlike -L/-R/-W forward
# targets which the remote server reaches (R1-class). -o ProxyCommand= with a
# non-verb host stays a residual (R3-class, arbitrary command); named verbs inside
# it (nc/curl/...) are still caught by the raw-string extractors above.
ssh_emit_proxy_hosts() {
  local vchar="$1" value="$2" spec='' lc part
  case "$vchar" in
    J) spec="$value" ;;
    o) lc=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
       case "$lc" in proxyjump=*) spec="${value#*=}" ;; esac ;;
  esac
  [ -z "$spec" ] && return 0
  local IFS_save=$IFS; IFS=','
  for part in $spec; do emit_norm_host "$part"; done
  IFS=$IFS_save
}
ssh_hosts() {
  local seg body vchar value ch
  while IFS= read -r seg; do
    seg=$(printf '%s' "$seg" | sed -E 's/^ssh[[:space:]]+//I')
    local -a toks=(); read -ra toks <<< "$seg"
    local idx; for idx in "${!toks[@]}"; do toks[idx]="${toks[$idx]//[\'\"]/}"; done  # strip quotes
    local i=0 n=${#toks[@]} t host='' k
    while [ "$i" -lt "$n" ]; do
      t="${toks[$i]}"
      case "$t" in
        --) i=$((i+1)); [ "$i" -lt "$n" ] && host="${toks[$i]}"; break ;;
        -?*)
          body="${t#-}"; vchar=''; value=''
          for (( k=0; k<${#body}; k++ )); do
            ch="${body:$k:1}"
            case "$SSH_VALUE_FLAGS" in
              *" $ch "*)
                vchar="$ch"
                if [ $((k+1)) -lt ${#body} ]; then value="${body:$((k+1))}"
                else i=$((i+1)); value="${toks[$i]:-}"; fi
                break ;;
            esac
          done
          [ -n "$vchar" ] && ssh_emit_proxy_hosts "$vchar" "$value"
          ;;
        *) host="$t"; break ;;
      esac
      i=$((i+1))
    done
    [ -n "$host" ] && emit_norm_host "$host"
  done < <(printf '%s' "$CMD" | grep -oiE '\bssh[[:space:]]+[^;&|()]*')
}

# Extract destination hosts (mirrors Codex _egress_extract_hosts):
#  - scheme://authority  (strip userinfo, port, trailing dot)
#  - scp/rsync  user@host:
#  - nc/ncat/telnet  host port
URL_HOSTS=$(printf '%s' "$CMD" | grep -oiE '[a-z][a-z0-9+.-]*://[^/?#"'"'"' ]+' \
            | sed -E 's#^[a-z][a-z0-9+.-]*://##; s#^.*@##; s#:.*$##; s#\.$##' \
            | tr '[:upper:]' '[:lower:]')
SCP_HOSTS=$(printf '%s' "$CMD" | grep -oE '@[A-Za-z0-9.-]+:' | sed -E 's#^@##; s#:$##' \
            | tr '[:upper:]' '[:lower:]')
NC_HOSTS=$(printf '%s' "$CMD" \
            | grep -oiE '\b(nc|ncat|telnet)\b([[:space:]]+-[^[:space:]]+)*[[:space:]]+[A-Za-z0-9.-]+[[:space:]]+[0-9]+' \
            | grep -oE '[A-Za-z0-9.-]+[[:space:]]+[0-9]+$' | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
SSH_HOSTS=$(ssh_hosts)

# R2-G-C: extract hosts from dig/nslookup/drill/socat/host DNS tools.
# These are treated as network egress — the query target is the destination host.
# [R2-G-C]
DNS_HOSTS=''
# dig [@server] [name] — server is optional, name is the query target
DNS_HOSTS_DIG=$(printf '%s' "$CMD" | grep -oiE '\bdig\b[^;|&()]*' \
                | grep -oiP '(?<!\@)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+' 2>/dev/null \
                | tr '[:upper:]' '[:lower:]' || true)
DNS_HOSTS_NS=$(printf '%s' "$CMD" | grep -oiE '\bnslookup\b[^;|&()]*' \
               | grep -oE '[A-Za-z0-9][A-Za-z0-9.-]+' | grep '\.' | tr '[:upper:]' '[:lower:]' || true)
DNS_HOSTS_SOCAT=$(printf '%s' "$CMD" | grep -oiE '\bsocat\b[^;|&()]*' \
                  | grep -oiE 'TCP[46]?:[A-Za-z0-9.-]+:[0-9]+' \
                  | sed -E 's/TCP[46]?://i; s/:[0-9]+$//' | tr '[:upper:]' '[:lower:]' || true)
DNS_HOSTS=$(printf '%s\n%s\n%s\n' "$DNS_HOSTS_DIG" "$DNS_HOSTS_NS" "$DNS_HOSTS_SOCAT" | sed '/^$/d' | sort -u)

HOSTS=$(printf '%s\n%s\n%s\n%s\n%s\n' "$URL_HOSTS" "$SCP_HOSTS" "$NC_HOSTS" "$SSH_HOSTS" "$DNS_HOSTS" | sed '/^$/d' | sort -u)

# ── R2-G-A: download-then-exec via allowed host ──────────────────────────────
# Detect the compound pattern: fetch to a file (-o <path> / --output <path>)
# followed by execution of that same path (bash/sh/source/./interpreter + path).
# Also catches fetch-to-/tmp followed by any exec of a /tmp path.
# Fires BEFORE the host allow-list check so an allow-listed host cannot be used
# as a staging server to deliver and execute arbitrary code.
# [R2-G-A]
detect_download_then_exec() {
  local cmd="$1"

  # 1. Extract output paths from -o <path> / --output <path> / --output=<path>
  local out_paths
  out_paths=$(printf '%s' "$cmd" \
    | grep -oiE '(-o[[:space:]]+[^[:space:]]+|--output[[:space:]]+[^[:space:]]+|--output=[^[:space:]]+)' \
    | sed -E 's/^(-o[[:space:]]+|--output[[:space:]]+|--output=)//')

  # 2. Check each extracted output path for subsequent execution
  while IFS= read -r opath; do
    [ -z "$opath" ] && continue
    # Strip quotes that may wrap the path
    opath="${opath//\'/}"
    opath="${opath//\"/}"

    # Check if the same path appears after an exec verb (bash|sh|zsh|fish|python*|ruby|perl|node|source|\.)
    # Use grep with the literal path (escaped for regex)
    escaped_path=$(printf '%s' "$opath" | sed 's/[.[\*^$(){}+?|]/\\&/g')
    if printf '%s' "$cmd" | grep -qiE "(bash|sh|zsh|fish|python[0-9.]*|ruby|perl|node|source|\.)[[:space:]]+[\"']?${escaped_path}[\"']?([[:space:]]|$|;|&&|\|\|)"; then
      deny "Blocked (bash-egress R2-G-A): download-then-exec detected — fetching to '$opath' then executing it. Download to a non-executable path, inspect the script, then run it explicitly only if safe."
    fi
  done <<< "$out_paths"

  # 3. Catch fetch-to-/tmp followed by ANY exec of a /tmp path (even a different filename)
  # If curl/wget writes to /tmp AND any shell exec of /tmp/... appears in the same command
  if printf '%s' "$cmd" | grep -qiE '\b(curl|wget)\b.*-o[[:space:]]*/tmp/' || \
     printf '%s' "$cmd" | grep -qiE '\b(curl|wget)\b.*--output[[:space:]]*/tmp/'; then
    if printf '%s' "$cmd" | grep -qiE '\b(bash|sh|zsh|fish|python[0-9.]*|ruby|perl|node|source)\b[[:space:]]+["\x27]?/tmp/'; then
      deny "Blocked (bash-egress R2-G-A): fetch to /tmp followed by execution of a /tmp path. This is a common download-then-exec staging pattern."
    fi
  fi
}

# Only invoke when curl or wget is present and the command has a potential exec verb
if printf '%s' "$CMD" | grep -qiE '\b(curl|wget)\b' && \
   printf '%s' "$CMD" | grep -qiE '\b(bash|sh|zsh|fish|python[0-9.]*|ruby|perl|node|source)\b|(\s|;|&&)\.[[:space:]]'; then
  detect_download_then_exec "$CMD"
fi

if [ -z "$HOSTS" ]; then
  deny "Blocked (bash-egress): network shell command with no verifiable destination host (fail-closed). Use a scheme-qualified URL (e.g. http://localhost:PORT)."
fi
while IFS= read -r h; do
  [ -z "$h" ] && continue
  if ! host_allowed "$h"; then
    deny "Blocked (bash-egress): shell egress to non-allowlisted host '$h'. Add it to egress.allow_hosts in the shared policy or use an allowed destination."
  fi
done <<< "$HOSTS"

exit 0
