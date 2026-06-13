# codex-t11-3-push-to-main-refs.md

**Finding ID:** F3 port  
**Severity:** MEDIUM  
**CC counterpart:** `patch-08-git-safety.sh` 2026-06-12 fix (CC-side refs/heads/ prefix acceptance)  
**File:** `~/.codex/hooks/pre_tool_use_dispatch.py`

## Gap

`DENY_PATTERNS` lines 72–79 block push-to-main with two patterns:

```python
(
    r"\bgit\s+push\b[^\n]*(?::(?:main|master)\b|\s(?:main|master)\s*$)",
    "Push targeting main/master is blocked by hook. Open a PR instead.",
),
(
    r"\bgit\s+push\b[^\n]*\s\+\S+:(?:main|master)\b",
    "Force push (+refspec) to main/master is blocked by hook.",
),
```

Neither pattern matches the full refspec form that git accepts and GitHub Actions commonly emits:

```bash
git push origin HEAD:refs/heads/main          # ← misses pattern 1
git push origin refs/heads/feature:refs/heads/main   # ← misses pattern 1 and 2
git push origin +HEAD:refs/heads/main         # ← misses pattern 2
```

The `:(?:main|master)\b` group requires the branch name immediately after `:`, but
`refs/heads/` sits between them in full refspecs.

## Patterns to replace

### Pattern 1 (lines 72–75) — plain push to main/master

**Current:**
```python
(
    r"\bgit\s+push\b[^\n]*(?::(?:main|master)\b|\s(?:main|master)\s*$)",
    "Push targeting main/master is blocked by hook. Open a PR instead.",
),
```

**Replace with:**
```python
(
    r"\bgit\s+push\b[^\n]*"
    r"(?::(?:refs/heads/)?(?:main|master)\b|\s(?:main|master)\s*$)",
    "Push targeting main/master is blocked by hook. Open a PR instead.",
),
```

Change: add `(?:refs/heads/)?` optional group between `:` and the branch name.

### Pattern 2 (lines 76–79) — force refspec push to main/master

**Current:**
```python
(
    r"\bgit\s+push\b[^\n]*\s\+\S+:(?:main|master)\b",
    "Force push (+refspec) to main/master is blocked by hook.",
),
```

**Replace with:**
```python
(
    r"\bgit\s+push\b[^\n]*\s\+\S+:(?:refs/heads/)?(?:main|master)\b",
    "Force push (+refspec) to main/master is blocked by hook.",
),
```

Change: add `(?:refs/heads/)?` optional group between `:` and the branch name.

## Full diff (lines 72–79)

```diff
-    (
-        r"\bgit\s+push\b[^\n]*(?::(?:main|master)\b|\s(?:main|master)\s*$)",
-        "Push targeting main/master is blocked by hook. Open a PR instead.",
-    ),
-    (
-        r"\bgit\s+push\b[^\n]*\s\+\S+:(?:main|master)\b",
-        "Force push (+refspec) to main/master is blocked by hook.",
-    ),
+    (
+        r"\bgit\s+push\b[^\n]*"
+        r"(?::(?:refs/heads/)?(?:main|master)\b|\s(?:main|master)\s*$)",
+        "Push targeting main/master is blocked by hook. Open a PR instead.",
+    ),
+    (
+        r"\bgit\s+push\b[^\n]*\s\+\S+:(?:refs/heads/)?(?:main|master)\b",
+        "Force push (+refspec) to main/master is blocked by hook.",
+    ),
```

## Self-test

### Quick inline regex verification (no hook needed)

```python
import re

old1 = r"\bgit\s+push\b[^\n]*(?::(?:main|master)\b|\s(?:main|master)\s*$)"
new1 = r"\bgit\s+push\b[^\n]*(?::(?:refs/heads/)?(?:main|master)\b|\s(?:main|master)\s*$)"

old2 = r"\bgit\s+push\b[^\n]*\s\+\S+:(?:main|master)\b"
new2 = r"\bgit\s+push\b[^\n]*\s\+\S+:(?:refs/heads/)?(?:main|master)\b"

cases = [
    # (command, should_match_old, should_match_new)
    ("git push origin HEAD:refs/heads/main",       False, True),
    ("git push origin +HEAD:refs/heads/main",       False, True),
    ("git push origin refs/heads/feat:refs/heads/master", False, True),
    ("git push origin HEAD:main",                  True,  True),   # still caught
    ("git push origin main",                       True,  True),   # still caught
    ("git push origin +feat:main",                 True,  True),   # still caught
    ("git push origin +feat:refs/heads/main",      False, True),
    ("git push origin feat:refs/heads/develop",    False, False),  # safe branch, allow
]

for cmd, old_should, new_should in cases:
    old_hit = bool(re.search(old1, cmd, re.I) or re.search(old2, cmd, re.I))
    new_hit = bool(re.search(new1, cmd, re.I) or re.search(new2, cmd, re.I))
    status = "OK" if (old_hit == old_should and new_hit == new_should) else "FAIL"
    print(f"{status}  old={old_hit} new={new_hit}  {cmd!r}")
```

Run this in the staged self-test script to confirm all 8 cases pass before applying.

### New test event: `tests/t11-f3-push-refs-heads-main.json`

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "git push origin HEAD:refs/heads/main"
  }
}
```

Expected pre-patch: EXIT:0, ALLOW (gap confirmed)
Expected post-patch: EXIT:0, DENY with "Push targeting main/master is blocked"

## APPLY note

1. Open `~/.codex/hooks/pre_tool_use_dispatch.py`.
2. Replace lines 72–79 with the two updated tuples above (unified diff shown).
3. Run the inline regex test (8 cases, all should print "OK").
4. Run `python3 <staged-copy> < tests/t11-f3-push-refs-heads-main.json` → expect DENY.
5. Verify existing tests still pass: `git push origin main` and `git push origin +feat:main`
   must still be caught (both remain in the new patterns).
