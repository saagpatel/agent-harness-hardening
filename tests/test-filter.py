#!/usr/bin/env python3
"""Test whether tar command matches the egress guard's network-verb pre-filter regex."""

import re

# Exact pattern from bash-egress-guard.sh line 315
NET_VERB_RE = re.compile(
    r"\b(curl|wget|scp|rsync|ncat|telnet|sftp|ftp|ssh)\b|(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)",
    re.IGNORECASE,
)

test_cmds = [
    "tar cf /tmp/ssh_bundle.tar ~/.ssh/",
    "tar cf - ~/.ssh/ > /tmp/ssh_bundle.tar",
    "zip -r /tmp/creds.zip ~/.ssh/ ~/.aws/",
    "zip - ~/.ssh/id_rsa > /tmp/key.zip",
    "cpio -o < /tmp/list > /tmp/creds.cpio",
    "pax -w ~/.ssh/ > /tmp/ssh.pax",
    # Also test zip writing to ~/.claude (write bypass angle)
    "zip /tmp/x.zip ~/.ssh/id_rsa",
]

for cmd in test_cmds:
    match = NET_VERB_RE.search(cmd)
    verdict = (
        "GUARDED (network verb match)"
        if match
        else "UNGUARDED (passes filter -> ALLOW)"
    )
    print(f"CMD: {cmd!r}")
    print(f"  -> {verdict}")
    print()
