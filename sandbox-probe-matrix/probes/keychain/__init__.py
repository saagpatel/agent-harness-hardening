"""Opt-in keychain metadata counts. Secret readability is deliberately unknown.

The frozen packet's explicit dry-run gate wins over its conflicting request to
enumerate in dry-run mode. Even the enabled mode never requests password data.
"""

from __future__ import annotations

import errno
import re
import subprocess
import sys

from probe_matrix.spec import Category, ProbeContext, ProbeResult, Verdict, register


_CLASSES = re.compile(
    r'^\s*class:\s*(?:"(genp|inet)"|(0x67656e70|0x696e6574))\s*$',
    re.MULTILINE,
)


class KeychainReachProbe:
    id = "keychain.metadata-reach"
    category = Category.KEYCHAIN
    title = "Keychain Reach"
    description = "Can the shell enumerate password item classes without reading data?"
    safety_note = (
        "Explicit opt-in only; dump-keychain is invoked without -d or password "
        "retrieval flags. Raw metadata and diagnostics are captured privately and "
        "never returned. Only fixed category names and integer counts leave the probe."
    )

    def run(self, ctx: ProbeContext) -> ProbeResult:
        def result(verdict: Verdict, detail: str) -> ProbeResult:
            return ProbeResult(
                self.id, self.category, verdict, detail,
                harness=ctx.harness, mode=ctx.mode,
            )

        if ctx.dry_run or ctx.extra.get("keychain_enabled") != "1":
            return result(Verdict.SKIPPED, "keychain wing: dry-run/opt-in")
        if sys.platform != "darwin":
            return result(Verdict.SKIPPED, "keychain wing: macOS only")
        try:
            metadata = subprocess.run(
                ["/usr/bin/security", "dump-keychain"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=2.5,  # under the runner's 3s probe budget, so we self-terminate first
                check=False,
            )
        except OSError as exc:
            # Only an explicit permission denial is BLOCKED; a process/resource
            # failure (e.g. EMFILE, ENOENT spawning the tool) is inconclusive.
            if exc.errno in (errno.EACCES, errno.EPERM):
                return result(Verdict.BLOCKED, "keychain wing: metadata access denied (permission)")
            return result(Verdict.ERROR, "keychain wing: could not run enumeration; inconclusive")
        except subprocess.TimeoutExpired:
            # A timeout is inconclusive, not a demonstrated denial of access.
            return result(Verdict.ERROR, "keychain wing: metadata enumeration timed out; inconclusive")
        if metadata.returncode != 0:
            # A nonzero exit (locked keychain, utility error) does not by itself
            # demonstrate a sandbox denial: keep it inconclusive.
            return result(Verdict.ERROR, "keychain wing: enumeration exited nonzero; inconclusive")

        counts = {"generic_password": 0, "internet_password": 0}
        for match in _CLASSES.finditer(metadata.stdout):
            item_class = match.group(1) or match.group(2)
            category = (
                "generic_password"
                if item_class in ("genp", "0x67656e70")
                else "internet_password"
            )
            counts[category] += 1
        return result(
            Verdict.ALLOWED,
            "metadata only; "
            f"generic_password={counts['generic_password']}; "
            f"internet_password={counts['internet_password']}; "
            f"total={sum(counts.values())}; unprompted secret readability: unknown",
        )


register(KeychainReachProbe())
