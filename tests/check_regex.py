import re

fallback = [
    r"\.ssh",
    r"\.aws",
    r"\.gnupg",
    r"\.config/op",
    r"\.config/gcloud",
    r"\.docker/config\.json",
    r"\.kube",
    r"\.netrc",
    r"\.pypirc",
    r"\.npmrc",
    r"\.git-credentials",
    r"\.gem/credentials",
    r"\.anthropic",
    r"\.claude/\.tokens",
    r"\.codex/auth\.json",
    r"\.codex/\.credentials\.json",
]
segs = "|".join(fallback)
pat = re.compile(
    r"(?:/Users/operator/|~/|\$HOME/)(?:" + segs + r")"
    r"|\bid_(?:rsa|ed25519|ecdsa)\b",
    re.IGNORECASE,
)

CODEX_SELF_WRITE_RE = re.compile(
    r"(?:>>?|\b(?:tee|cp|mv|install|ln|dd)\b|\bsed\b[^\n]*\s-i)"
    r"[^\n]*\.codex/(?:hooks/|agents/|config\.toml|hooks\.json)\b",
    re.IGNORECASE,
)

tests = [
    ("/Users/operator/.claude/mcp-gate-policy.json", "SENSITIVE_PATH_RE"),
    ("/Users/operator/.claude/hooks/pre_tool_use_dispatch.py", "SENSITIVE_PATH_RE"),
    ("/Users/operator/.codex/hooks/pre_tool_use_dispatch.py", "SENSITIVE_PATH_RE"),
    ("/Users/operator/.ssh/id_rsa", "SENSITIVE_PATH_RE"),
    ("/Users/operator/.anthropic/token", "SENSITIVE_PATH_RE"),
]
for t, label in tests:
    m = pat.search(t)
    print("MATCH={:<5}  [{}]  {}".format(str(bool(m)), label, t))

# Also test CODEX_SELF_WRITE_RE against the python3 interpreter write
cmds = [
    "python3 -c \"open('/Users/operator/.claude/mcp-gate-policy.json','w').write('{}')\"",
    "python3 -c \"open('/Users/operator/.codex/hooks/pre_tool_use_dispatch.py','w').write('exit(0)')\"",
    "tee /Users/operator/.codex/hooks/pre_tool_use_dispatch.py < /tmp/evil.py",
]
for c in cmds:
    m2 = CODEX_SELF_WRITE_RE.search(c)
    print("SELF_WRITE_MATCH={:<5}  {}".format(str(bool(m2)), c[:80]))
