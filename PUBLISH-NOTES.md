# tournament-11 — published artifact notes

This directory is a **PII-free snapshot** of the session-11 harness-hardening set,
produced by `publish-scrub.py`. Read this before reusing anything here.

## What was scrubbed
Two identifying tokens were replaced with synthetic values, uniformly across guard
regexes and attack fixtures alike (so the set stays internally self-consistent — a
fixture path still matches the regex meant to catch it):
- home path `/Users/<name>` -> **`/Users/operator`**
- the operator's GitHub handle (in policy allowlists) -> **`example-owner`**

No emails, private domains, or cost figures were present (test fixtures use obviously
synthetic addresses like `t@t.com`).

## This is a snapshot, not a runnable suite
- The test files still point `PYTHONPATH` at a live `~/.codex/hooks` and use the
  synthetic username, so they are **illustrative / review artifacts** — they are not
  expected to run green on an arbitrary machine.
- The authoritative red->green verification ran against the real working set (real
  paths, byte-identical to the operator's live hooks) before publication.

## How the patches actually apply (drift-safe)
- Codex parity lands via **splice-onto-current-live** (`codex-t11-splice.py`,
  driven by `apply-codex-t11.sh`), never a blind copy of a frozen snapshot — a stale
  snapshot would silently revert protections the live hook gained out-of-band.
- The CC cp-based installer (`apply-tournament-11.sh`) is gated by
  `harness-drift-check.sh`, which refuses to copy over any target that has DIVERGED
  from its staged source.
