"""Execution reachability, without GUI launch or user startup configuration."""

from __future__ import annotations

import subprocess
import sys

from probe_matrix.spec import Category, Verdict, register
from probes.core._base import TIMEOUT, CoreProbe, Outcome


def _exec(argv: list[str]) -> Outcome:
    result = subprocess.run(
        argv,
        timeout=TIMEOUT,
        check=False,
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        return Verdict.ERROR, "child ran but returned nonzero; boundary denial unconfirmed"
    return Verdict.ALLOWED, "bounded no-op execution or non-launching lookup succeeded"


def _app_lookup() -> Outcome:
    if sys.platform != "darwin":
        return Verdict.SKIPPED, "non-launching application lookup is macOS-only"
    return _exec(["/usr/bin/open", "-Ra", "Finder"])


_SAFE = "Fixed no-op command or open -Ra existence check; 2s timeout, no GUI launch or output."
for _id, _title, _action in [
    ("app.exec-true", "Execute system no-op", lambda c: _exec(["/usr/bin/true"])),
    (
        "app.exec-python",
        "Execute isolated Python no-op",
        lambda c: _exec([sys.executable, "-I", "-c", "pass"]),
    ),
    ("app.exec-shell", "Execute shell built-in no-op", lambda c: _exec(["/bin/sh", "-c", ":"])),
    (
        "app.exec-env",
        "Execute no-op with empty environment",
        lambda c: _exec(["/usr/bin/env", "-i", "/usr/bin/true"]),
    ),
    ("app.lookup", "Look up installed app without launch", lambda c: _app_lookup()),
]:
    register(CoreProbe(_id, Category.APP_LAUNCH, _title, _title + "?", _SAFE, _action))
