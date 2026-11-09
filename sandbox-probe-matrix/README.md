# Sandbox Probe Matrix

A rerunnable test of what actually escapes an agent's sandbox, presented as one
clean grid. About thirty small, safe boundary probes each ask one question — can
it read a protected directory, write where it should not, reach a local socket,
resolve a name, launch another app — run inside each configured harness and mode,
and scored **allowed** or **blocked**. A saved baseline lets a rerun diff against
the last run and flag any cell that flipped to **red** (blocked -> allowed).

Three wings extend the core grid:
- **Shared Temp Leak** — can one session read what another wrote to its temp area?
- **Worktree Hook Bleed** — can an agent in an isolated worktree change what the
  main checkout runs, via shared git config? (reachability checked read-only; no
  hook is ever executed)
- **Keychain Reach** — which saved secrets can a plain shell read unprompted?
  **Dry-run by default: counts and categories only, never values.**

## Safety (non-negotiable)

- Every probe is **read-only and non-destructive**: it demonstrates reachability,
  never damage, persistence, or exfiltration.
- **Own machine and own accounts only.** The runner refuses non-local / non-owned
  targets before any probe runs.
- The keychain wing **never prints secret values**.
- Committed output carries **no real paths, names, emails, or secrets** — host
  identity is a salted, truncated fingerprint only.
- A **red cell is a finding to act on, not a resolved issue.**

## Usage

```bash
uv run spm run --list                     # list probes
uv run spm run --harness shell --mode default
uv run spm report --baseline baseline.json --diff
```

Stdlib-only; `uv` is used for the dev toolchain (pytest, pyright) only.
