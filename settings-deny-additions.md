# settings.json deny-additions (tournament-11)

Operator-applied via `jq` — do NOT let an agent write settings.json directly.
Adding to `permissions.deny` is **de-escalation** (safe): it reduces attack
surface. No safety-posture weakening; no protected key changes.

## How to apply

```bash
# Dry-run first — verify the output looks right, then pipe to sponge/tee.
jq '
  .permissions.deny += [
    "Read(~/.claude/.tokens/**)",
    "Glob(~/.claude/.tokens/**)",
    "ListMcpResourcesTool(*)",
    "ReadMcpResourceTool(*)"
  ] | .permissions.deny |= unique
' ~/.claude/settings.json
```

When satisfied:

```bash
cp ~/.claude/settings.json ~/.claude/settings.json.pre-t11-$(date +%Y%m%d-%H%M%S).bak
jq '
  .permissions.deny += [
    "Read(~/.claude/.tokens/**)",
    "Glob(~/.claude/.tokens/**)",
    "ListMcpResourcesTool(*)",
    "ReadMcpResourceTool(*)"
  ] | .permissions.deny |= unique
' ~/.claude/settings.json > /tmp/settings-patched.json && mv /tmp/settings-patched.json ~/.claude/settings.json
```

---

## Exact JSON entries to add

```json
"Read(~/.claude/.tokens/**)"
```
**Finding R5-b** — token-dir read gate. Prevents any MCP or Bash call from
reading `~/.claude/.tokens/*` (API keys, session tokens). Currently not in
deny; paired with the Glob entry below.

```json
"Glob(~/.claude/.tokens/**)"
```
**Finding R5-b** — token-dir glob gate. Prevents directory-listing the tokens
path, which would reveal token filenames even without reading content.

```json
"ListMcpResourcesTool(*)"
```
**Finding R5-a** — MCP resource listing gate. `ListMcpResourcesTool` exposes
the full MCP resource tree; gating it forces the call through `mcp-guard.sh`
first. The wildcard `(*)` matches any server/resource argument.

```json
"ReadMcpResourceTool(*)"
```
**Finding R5-a** — MCP resource read gate. `ReadMcpResourceTool` reads
arbitrary MCP resource URIs; gating it prevents exfiltration of vault content,
credentials, or config files that MCP servers expose as resources.

---

## Post-apply verification

After applying, confirm the four rules are present and the total deny count
increased by 4 (or fewer if any already existed):

```bash
jq '.permissions.deny | map(select(
  . == "Read(~/.claude/.tokens/**)" or
  . == "Glob(~/.claude/.tokens/**)" or
  . == "ListMcpResourcesTool(*)" or
  . == "ReadMcpResourceTool(*)"
))' ~/.claude/settings.json
# Expected: array of all 4 strings

jq '.permissions.deny | length' ~/.claude/settings.json
# Expected: previous count + 4 (was 38 → now 42)
```

---

## Note on PERM_DENY_MIN in harness-config-validate.sh

If you apply these additions, the patched validator's `PERM_DENY_MIN=20` floor
is not affected (38 → 42 is above the floor). If you want to raise the floor
to track the new baseline, update `PERM_DENY_MIN` in the patched
`harness-config-validate.sh` before installing it.
