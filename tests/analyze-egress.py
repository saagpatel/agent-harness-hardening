#!/usr/bin/env python3
"""Analyze why bash-egress-guard fires on swift credential-read command."""

import re

CMD = r"""swift -e 'import Foundation; print(try! String(contentsOfFile: (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/id_ed25519"), encoding: .utf8))'"""

print("CMD:", repr(CMD))
print()

# The exact pattern from bash-egress-guard.sh line 315:
# '\b(curl|wget|scp|rsync|ncat|telnet|sftp|ftp|ssh)\b|(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)'
# NOTE: bash grep -E does NOT support \b as word boundary on macOS/BSD grep!
# BSD grep treats \b as a literal 'b' or as a word boundary depending on version.
# macOS grep is BSD grep -- let's check what \b means there.

# In Python re, \b IS a word boundary:
pat_py = r"\b(curl|wget|scp|rsync|ncat|telnet|sftp|ftp|ssh)\b|(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)"
m = re.search(pat_py, CMD, re.IGNORECASE | re.MULTILINE)
print("Python re match (\\b = word boundary):", m)
if m:
    print("  matched at:", m.start(), m.group())

# Without \b (treat as literal 'b' - BSD grep behavior):
# On macOS, grep -E '\b' matches the literal character 'b' NOT a word boundary
# BSD grep ERE: \b is not a recognized escape, treated as literal 'b'
# So '\bssh\b' becomes 'bsshb' in BSD ERE — clearly not right
# Actually macOS grep: \b in ERE is an undefined escape, behavior is implementation-specific.
# Let's check if 'swift' contains 'ftp':
print()
print("Does 'swift' contain 'ftp'?", "ftp" in "swift".lower())
print("Does 'swift' contain 'scp'?", "scp" in "swift".lower())
print("Does 'swift' contain 'ssh'?", "ssh" in "swift".lower())

# Actually macOS (BSD) grep -E: \b is NOT defined in POSIX ERE
# Some versions treat it as \< \> (word boundary), others ignore it
# The key question: does macOS grep -E treat 'sftp' matching inside 'swift'?
# 'swift' = s,w,i,f,t -- no 'sftp', no 'ftp', no 'scp', no 'ssh'

# BUT WAIT: look at the full command for 'ftp' or 'sftp':
print()
print("Checking full CMD for each verb:")
for verb in ["curl", "wget", "scp", "rsync", "ncat", "telnet", "sftp", "ftp", "ssh"]:
    if verb in CMD.lower():
        idx = CMD.lower().index(verb)
        print(
            f"  FOUND '{verb}' at index {idx}: ...{CMD[max(0, idx - 5) : idx + len(verb) + 5]}..."
        )

# Check nc
print()
print("Checking for nc pattern:")
nc_pat = r"(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)"
for m in re.finditer(nc_pat, CMD, re.IGNORECASE | re.MULTILINE):
    print(
        f"  nc match at {m.start()}: {repr(CMD[max(0, m.start() - 3) : m.end() + 3])}"
    )
