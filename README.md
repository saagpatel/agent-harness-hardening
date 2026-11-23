# Tournament-11 Harness Hardening — Staging

Blue-team patches for the config-integrity layer. Installing the staged hooks
is an operator step.

## Quick start: verify from a clean clone

Run the regression test directly from the clone. It creates fixtures under
`/tmp` and removes them on exit. If live hooks exist under `~/.claude`,
the test also runs them for comparison.

Prerequisites: macOS or Linux with `bash`, `jq` and a writable `/tmp`. The
Class-13 check needs jq in one of the locations listed below or a trusted
absolute path in `JQ`. Cloning needs Git and network access. The regression
test runs offline without a build step or credentials.

```bash
git clone -b publish https://github.com/saagpatel/agent-harness-hardening.git
cd agent-harness-hardening
bash tests/test-config-integrity.sh
```

Expected: `6/6 tests passed`. Each "red" check reports `SKIP/PASS` if its
live hook is absent and counts toward the total. The four checks against the
staged files still run.

Other scripts and fixtures under `tests/`, including `test-mcp-gate.sh` and
the `r*-*.json` payloads, document the operator's hook set. Several runners
expect live hooks or operator-specific paths. See [PUBLISH-NOTES.md](PUBLISH-NOTES.md).
The [sandbox probe matrix](sandbox-probe-matrix/README.md) is a separate Python project.

## Files

| Staged file | Installs to | Findings addressed |
|---|---|---|
| `harness-config-validate.sh` | `~/.claude/hooks/harness-config-validate.sh` | R3-M, R2-F |
| `deny.sh` | `~/.claude/hooks/lib/deny.sh` | Class-13 |
| `settings-deny-additions.md` | operator-applied jq snippet | R5-a, R5-b |
| `tests/test-config-integrity.sh` | run from the clone | test harness |

The repo also holds further guard hooks, installers and fixtures (see
`PUBLISH-NOTES.md`); the table covers the config-integrity changes.

## Install steps (operator only, onto a machine that already has the harness in `~/.claude`)

These steps modify `~/.claude` and are not needed to run the quick start above.
Run them from the root of your clone.

```bash
# 1. Diff each file before copying.
diff ~/.claude/hooks/harness-config-validate.sh harness-config-validate.sh
diff ~/.claude/hooks/lib/deny.sh deny.sh

# 2. Backup live files.
cp ~/.claude/hooks/harness-config-validate.sh \
   ~/.claude/hooks/harness-config-validate.sh.pre-t11-$(date +%Y%m%d-%H%M%S).bak
cp ~/.claude/hooks/lib/deny.sh \
   ~/.claude/hooks/lib/deny.sh.pre-t11-$(date +%Y%m%d-%H%M%S).bak

# 3. Install the two reviewed hooks.
cp harness-config-validate.sh ~/.claude/hooks/harness-config-validate.sh
cp deny.sh ~/.claude/hooks/lib/deny.sh

# 4. Apply settings.json deny additions — see settings-deny-additions.md.

# 5. Run the staged regression test from the clone.
bash tests/test-config-integrity.sh
```

If your harness supplies its own `~/.claude/hooks/tests/run-tests.sh`,
use that runner for its installed-hook checks as well.

## Test results (tournament-11 baseline)

Selected output with no live hooks installed:

```
  SKIP/PASS: R3-M red, no live validator installed in ~/.claude (clean clone)
  PASS: R3-M green — PATCHED validator BLOCKS merge-asymmetry attack (deny-shrink or required-rule check triggered)
  PASS: R3-M regression — clean config passes without false-positive rollback
  PASS: R2-F green — PATCHED validator blocks CODEX_EGRESS_POLICY injection
  SKIP/PASS: Class-13 red, no live deny.sh installed in ~/.claude (clean clone)
  PASS: Class-13 green — PATCHED deny.sh still emits valid deny JSON with poisoned PATH (hardened)
6/6 tests passed
```

The R3-M fixture empties `hard_deny` as well as `permissions.deny`. When
both settings files exist, the patched validator checks the deny counts and
required rules under both array-union and array-replacement merge semantics.

## Residual limits

See bottom of this document.

---

## Residual limits

1. **Snapshot race window.** The installed harness supplies the PreToolUse
   snapshot hook. On a failed PostToolUse check, the staged validator restores
   the latest available backup for that filename, which may predate the write.
   If no backup exists, it logs the failure, attempts a macOS notification and
   emits a block decision. The written file still needs repair. Direct writes
   outside the hook lifecycle do not trigger validation.

2. **Temporary files.** The validator uses `mktemp /tmp/prefix.XXXXXX` to
   allocate a distinct file for each merge. These files require a writable
   `/tmp`.

3. **deny.sh PATH hardcoding.** The known-safe jq locations are: `/opt/homebrew/bin/jq`,
   `/usr/local/bin/jq`, `/usr/bin/jq`, `/bin/jq`, `/opt/local/bin/jq`,
   `/nix/var/nix/profiles/default/bin/jq`. An executable absolute path
   supplied in `JQ` takes precedence. If none is available, the script checks
   `command -v jq` for an executable absolute path. It uses `printf` only
   when the selected executable is missing or no executable was found.

4. **R2-F hook checks.** The validator requires at least eight nested
   PreToolUse hook entries and a timeout of at least five seconds on each.
   It does not check the hook script names.

5. **Settings deny additions.** For the manual install above, apply the four
   entries in `settings-deny-additions.md`. The separate
   `apply-tournament-11.sh` installer includes them in its apply step.
   The validator keeps its `PERM_DENY_MIN=20` floor regardless of the
   resulting number of unique deny entries.
