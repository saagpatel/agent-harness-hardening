#!/bin/bash
# protect-claude-writes.sh — PreToolUse(Bash) guard
#
# Closes red-team finding B10 (verified 2026-06-10): protect-files.sh guards the
# NATIVE Edit/Write tools (matcher: Read|Edit|Write|MultiEdit) but NOT the Bash
# tool, so a shell redirection / tee / cp into ~/.claude/{hooks,agents,
# settings*.json,mcp-gate-policy.json} or ~/.claude.json could neuter a harness
# guard with no block. This is the Bash-side twin of protect-sensitive-reads.sh
# (which guards Bash *reads* of credential dirs).
#
# HARDENED 2026-06-12 (session #1 harness threat-model — finding F1, CRITICAL):
# the original verb allowlist (tee|cp|mv|install|rsync|ln|truncate, redirects,
# sed -i, dd, chmod) was bypassed three ways, all reproduced:
#   (a) language interpreters that write the file at runtime:
#       python3 -c "open('~/.claude/hooks/x.sh','w').write('exit 0')"
#       node   -e "require('fs').writeFileSync('~/.claude/settings.json','{}')"
#   (b) variable-indirection redirect, which also slipped the fast path because
#       the path matcher required a trailing slash:
#       X=~/.claude/hooks; printf 'exit 0' > $X/db-guard.sh
#   (c) cd into the protected dir then a relative-path write.
# Fix: (1) path matcher now uses a word boundary, not a required trailing slash;
#      (2) interpreters touching a protected path are treated as opaque writes;
#      (3) a protected-path variable assignment OR a cd-into-protected-dir, when
#          the command also carries any write indicator, is denied.
#
# HARDENED tournament-11 (findings T1/C1/R2-I/R4-O/R4-Q):
#   T1 (CRITICAL): .tokens/ was not in the protected-path family; touch / shell
#      redirects / interpreter writes to ~/.claude/.tokens/ were allowed. Legit
#      writer is the operator's claude-confirm binary, never the agent's Bash.
#   C1 (HIGH): interpreter list lacked swift|swiftc|xcrun|lldb|gdb|osacompile|
#      go|java|sqlite3. Added. Note: this list is inherently incomplete — the
#      behavioral catch (path-match + write-indicator) is the durable floor.
#   R2-I (HIGH): ~/.claude/skills/*/SKILL.md was not in the protected write
#      targets; a Bash redirect could overwrite skill definitions.
#   R4-O (HIGH): ANSI-C quoting ($'…') or $(printf …)/$(echo -e …) near a
#      protected path is obfuscation — deny proactively.
#   R4-Q (MED): unbounded command length allows multi-grep timeout → fail-open.
#      Deny immediately if COMMAND exceeds 512 KiB.
#
# READS of ~/.claude are intentionally allowed (the agent legitimately inspects
# settings/hooks) — only WRITES are denied. NOT covered here by design:
# ~/.claude/CLAUDE.md and rules/*.md (operator carve-out + harness-config-validate
# workflow). ~/.claude/skills/**  is guarded by R2-I below (SKILL.md write-
# protected) and by skill-install-gate.sh for the native Write/Edit path.
#
# INSTALL (operator only — the agent cannot write to ~/.claude/hooks):
#   cp ~/Projects/fable-outputs/staging/tournament-11/protect-claude-writes.sh \
#      ~/.claude/hooks/protect-claude-writes.sh
#   chmod +x ~/.claude/hooks/protect-claude-writes.sh
#   # settings.json wiring is unchanged (already in the Bash matcher block).
#
# Known conservative behavior: a command that both references a protected path and
# carries a write indicator is denied even in rare read-out cases (e.g. `cp
# ~/.claude/hooks/x /backup`, or `python3 -c "print(open('~/.claude/hooks/x').read())"`).
# Run such intentional maintenance yourself with the ! prefix.
set -euo pipefail
INPUT=$(cat)

. "$HOME/.claude/hooks/lib/deny.sh"

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

# [R4-Q] Length gate: a command >512 KiB would cause multi-grep timeout → fail-open.
# Deny immediately; no legitimate agent command approaches this size.
if [ "${#COMMAND}" -gt 524288 ]; then
  deny "Blocked: command length ${#COMMAND} exceeds 524288-byte safety limit (finding R4-Q — length gate prevents grep timeout → fail-open)."
fi

# Home-dir matcher covering every spelling: $HOME, ${HOME}, ~, and the literal path.
HOME_ESC=$(printf '%s' "${HOME:-}" | sed 's/[][\/.^$*+?(){}|]/\\&/g')
H='(\$HOME|\$\{HOME\}|~'
[ -n "$HOME_ESC" ] && H="$H|$HOME_ESC"
H="$H)"

# Protected harness targets (write-protected) under the home dir.
# NOTE: (hooks|agents) ends on a word boundary, not a required '/', so that a
# reference like `~/.claude/hooks` (no trailing slash, e.g. assigned to a var or
# used as a cd target) still trips the fast path. `hooks-backup` etc. are a
# harmless conservative over-match.
#
# [T1] .tokens added: the only legit writer is the operator's claude-confirm binary,
#      never the agent's Bash tool. touch / redirect / interpreter writes are denied.
#
# [R2-I] skills/*/SKILL.md added: Bash redirect overwrites are denied; the native
#         Edit/Write path is covered by skill-install-gate.sh.
PP="${H}/\.claude/(hooks|agents|\.tokens)\b|${H}/\.claude/settings(\.local)?\.json|${H}/\.claude/mcp-gate-policy\.json|${H}/\.claude\.json|${H}/\.claude/skills/[^/]+/SKILL\.md"

# [C1/M2] Home-prefix-OPTIONAL variant. A runtime-constructed path carries no
# literal ~/$HOME prefix in the command string, e.g.
#   swift -e '… .write(toFile: NSHomeDirectory()+"/.claude/hooks/x.sh" …)'
#   python3 -c "open(os.path.expanduser('~')+'/.claude/hooks/x','w')"
# The home-anchored PP never matches these, so the interpreter check below never
# runs. PP_BARE matches the protected segment without the home anchor; combined
# with a write-indicator below it catches the runtime-path family. Conservative
# over-match on a project-local .claude (write-only; reads stay allowed).
PP_BARE="\.claude/(hooks|agents|\.tokens)\b|\.claude/settings(\.local)?\.json|\.claude/mcp-gate-policy\.json|\.claude\.json|\.claude/skills/[^/]+/SKILL\.md"
PP_ALL="(${PP}|${PP_BARE})"

# Fast path: no protected target referenced anywhere -> not our concern.
echo "$COMMAND" | grep -qE "$PP_ALL" || exit 0

# [R4-O] Obfuscation gate: ANSI-C quoting ($'…') or $(printf …)/$(echo -e …)
# adjacent to a protected path is a strong indicator of bypass attempt. Deny
# proactively — legitimate commands have no reason to encode a harness path.
if echo "$COMMAND" | grep -qE "\\\$'[^']*'" || \
   echo "$COMMAND" | grep -qE '\$\(printf|\$\(echo[[:space:]]+-e'; then
  deny "Blocked: suspected path obfuscation (ANSI-C quoting or \$(printf/echo -e) near a protected ~/.claude path — finding R4-O). Legitimate harness maintenance uses plain paths and the ! prefix."
fi

# A protected target is referenced. Deny if the command WRITES to it by any of the
# recognized mechanisms. Clauses are kept separate for readability.
DENYREASON="Blocked: Bash write to a protected ~/.claude harness file (hooks/, agents/, .tokens/, skills/*/SKILL.md, settings*.json, mcp-gate-policy.json, or ~/.claude.json). Harness guards change only via the operator's reviewed Edit workflow — never a shell write (closes findings B10 + F1 + T1 + R2-I). Reads are allowed. For intentional maintenance, run it yourself with the ! prefix."

# [C1] Interpreter list expanded: swift|swiftc|xcrun|lldb|gdb|osacompile|go|java|
#      sqlite3 added to the existing set. NOTE: this enumeration is inherently
#      incomplete — the behavioral catch (path-match + write-indicator in the
#      indirect-mechanisms block below) provides a durable second floor for any
#      interpreter not listed here.
# [T1] touch added to direct write-verb list (was missing; touch ~/.claude/.tokens/<hex>
#      was previously allowed).
# Direct mechanisms whose target is the protected path itself.
if   echo "$COMMAND" | grep -qE ">>?[[:space:]]*['\"]?${PP_ALL}" \
  || echo "$COMMAND" | grep -qE "\b(touch|tee|cp|mv|install|rsync|ln|truncate)\b[^|;&]*${PP_ALL}" \
  || echo "$COMMAND" | grep -qE "\bsed\b[^|;&]*-i[^|;&]*${PP_ALL}" \
  || echo "$COMMAND" | grep -qE "\bdd\b[^|;&]*\bof=[[:space:]]*['\"]?${PP_ALL}" \
  || echo "$COMMAND" | grep -qE "\b(chmod|chown)\b[^|;&]*${PP_ALL}" \
  || echo "$COMMAND" | grep -qE "\b(python3?|ruby|perl|node|deno|bun|php|lua|Rscript|tclsh|osascript|swift|swiftc|xcrun|lldb|gdb|osacompile|go|java|sqlite3)\b[^|;&]*${PP_ALL}"; then
  deny "$DENYREASON"
fi

# [C1/F7] Adjacency-free interpreter clause. The fast path already confirmed a
# protected path is referenced. A `;`/newline INSIDE a quoted -e/-c string splits
# the interpreter token from the path under the [^|;&]* adjacency above, e.g.
#   swift -e 'import Foundation; … .write(toFile: …/.claude/hooks/x.sh …)'
# So: protected-path-referenced + ANY interpreter token anywhere → deny. Reads via
# an interpreter are conservatively denied by design (run maintenance with !).
if echo "$COMMAND" | grep -qE "\b(python3?|ruby|perl|node|deno|bun|php|lua|Rscript|tclsh|osascript|swift|swiftc|xcrun|lldb|gdb|osacompile|go|java|sqlite3)\b"; then
  deny "$DENYREASON"
fi

# Indirect mechanisms: a protected-path variable assignment, or a cd into a
# protected dir, combined with ANY write indicator elsewhere in the command.
# [C1] Interpreter list in the write-indicator check also expanded to match above.
if echo "$COMMAND" | grep -qE "\b[A-Za-z_][A-Za-z0-9_]*=['\"]?(${H})/\.claude/(hooks|agents|\.tokens|settings|mcp-gate-policy|skills)" \
   || echo "$COMMAND" | grep -qE "\bcd[[:space:]]+['\"]?(${H})/\.claude/(hooks|agents|\.tokens)\b"; then
  if echo "$COMMAND" | grep -qE "(>>?|\b(touch|tee|cp|mv|install|rsync|ln|truncate|dd)\b|\b(python3?|ruby|perl|node|deno|bun|php|lua|Rscript|tclsh|osascript|swift|swiftc|xcrun|lldb|gdb|osacompile|go|java|sqlite3)\b)"; then
    deny "$DENYREASON"
  fi
fi
exit 0
