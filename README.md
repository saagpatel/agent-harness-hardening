# Tournament-11 Harness Hardening — Staging

Blue-team patches for the config-integrity layer. No live files are modified;
operator installs by copying and reviewing each file.

## Files

| Staged file | Installs to | Findings addressed |
|---|---|---|
| `harness-config-validate.sh` | `~/.claude/hooks/harness-config-validate.sh` | R3-M, R2-F |
| `deny.sh` | `~/.claude/hooks/lib/deny.sh` | Class-13 |
| `settings-deny-additions.md` | operator-applied jq snippet | R5-a, R5-b |
| `tests/test-config-integrity.sh` | `~/.claude/hooks/tests/` | test harness |

## Install steps

```bash
STAGING=~/Projects/fable-outputs/staging/tournament-11

# 1. Diff each file before copying.
diff ~/.claude/hooks/harness-config-validate.sh $STAGING/harness-config-validate.sh
diff ~/.claude/hooks/lib/deny.sh $STAGING/deny.sh

# 2. Backup live files.
cp ~/.claude/hooks/harness-config-validate.sh \
   ~/.claude/hooks/harness-config-validate.sh.pre-t11-$(date +%Y%m%d-%H%M%S).bak
cp ~/.claude/hooks/lib/deny.sh \
   ~/.claude/hooks/lib/deny.sh.pre-t11-$(date +%Y%m%d-%H%M%S).bak

# 3. Install (operator-run, not agent-run — protect-claude-writes.sh blocks agent writes to ~/.claude).
cp $STAGING/harness-config-validate.sh ~/.claude/hooks/harness-config-validate.sh
cp $STAGING/deny.sh ~/.claude/hooks/lib/deny.sh
cp $STAGING/tests/test-config-integrity.sh ~/.claude/hooks/tests/test-config-integrity.sh
chmod +x ~/.claude/hooks/tests/test-config-integrity.sh

# 4. Apply settings.json deny additions — see settings-deny-additions.md.

# 5. Run regression tests.
bash ~/.claude/hooks/tests/run-tests.sh
bash ~/.claude/hooks/tests/test-config-integrity.sh
```

## Test results (tournament-11 baseline)

```
6/6 tests passed

  SKIP/PASS: R3-M red — LIVE validator already blocks (no vulnerability to demonstrate)
  PASS: R3-M green — PATCHED validator BLOCKS merge-asymmetry attack
  PASS: R3-M regression — clean config passes without false-positive rollback
  PASS: R2-F green — PATCHED validator blocks CODEX_EGRESS_POLICY injection
  PASS: Class-13 red — LIVE deny.sh emits NOTHING with poisoned PATH (fail-open vulnerability confirmed)
  PASS: Class-13 green — PATCHED deny.sh still emits valid deny JSON with poisoned PATH (hardened)
```

Note on R3-M red: the live validator happened to block the basic attack via the
`hard_deny` count check (the attack payload also emptied `hard_deny`). The
patched validator adds defence-in-depth: it explicitly runs all sentinel and
count checks against a naive-merged config, so a crafted attack that preserves
counts but erases credential-deny rules is also blocked.

## Residual limits

See bottom of this document.

---

## Residual limits

1. **Snapshot race window.** `harness-config-snapshot.sh` (PreToolUse) runs
   before the write; `harness-config-validate.sh` (PostToolUse) runs after.
   A write that bypasses the PreToolUse hook (e.g., direct filesystem write
   outside Claude Code) has no snapshot to roll back from, so the validator
   logs the failure and blocks but cannot restore. Mitigation: the validator
   still emits a block decision and a macOS notification — silent corruption
   is prevented.

2. **mktemp namespace collision.** Multiple concurrent validator invocations
   sharing `/tmp` could create identically-named temp files. Mitigated in this
   patch by using bare `mktemp /tmp/prefix.XXXXXX` (no `.json` suffix) so the
   OS randomises the name correctly. A further hardening would use `mktemp -d`
   + a fixed name inside it, but that is not done here.

3. **deny.sh PATH hardcoding.** The known-safe jq locations are: `/opt/homebrew/bin/jq`,
   `/usr/local/bin/jq`, `/usr/bin/jq`, `/bin/jq`, `/opt/local/bin/jq`,
   `/nix/var/nix/profiles/default/bin/jq`. If jq is installed elsewhere (e.g.
   a custom prefix), the script falls back to `command -v jq` as a last resort
   — which is PATH-searchable. Add the non-standard path to the hardcoded list
   if needed. The printf fallback catches the absolute worst case.

4. **R2-F hooks check is count-only.** We verify PreToolUse hook count >= 8
   and timeout >= 5, but do not verify the specific hook script names. An
   attacker could replace the 8 hooks with 8 no-op scripts and pass the count
   check. A per-hook script-name allowlist would close this, but is complex to
   maintain without a centralized hook registry — deferred.

5. **settings.json deny-additions are not automatically installed.** The
   `settings-deny-additions.md` snippet must be applied by the operator. The
   validator's `PERM_DENY_MIN=20` floor does not auto-update after the
   additions; bump it to 42 in the patched validator before installing if you
   apply all four new deny entries.
