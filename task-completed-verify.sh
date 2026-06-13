#!/bin/bash
# TaskCompleted: type check + test gate by project type, with baseline-delta.
# Exit 2 blocks task completion and surfaces stderr to Claude.
#
# Layered gates:
#   1. Skip on CLAUDE_EFFORT=low
#   2. Skip if all working-tree changes are docs-only
#   3. Try the project-type gate (mypy/tsc/cargo check/swift/xcodebuild/go)
#   4. On failure, stash uncommitted changes, re-run gate on clean HEAD,
#      compare error sets. Block only if NEW errors were introduced.
set -euo pipefail

# -- Skip 1: low-effort tasks (v2.1.133+ effort awareness) -------------------
[ "${CLAUDE_EFFORT:-high}" = "low" ] && exit 0

# -- Skip 2: docs-only working-tree changes ----------------------------------
# FIX R3-J: empty-commit verify bypass.
#
# The old code exited 0 when `changed` was empty, which is also true for
# `git commit --allow-empty` (HEAD moved, nothing in the tree diff).
# New logic: when changed is empty AND we are in a git repo, distinguish
# between two cases:
#   (a) Genuine clean tree (no HEAD, or HEAD has real file changes) → still skip.
#   (b) Empty commit (HEAD exists, HEAD has a parent, but HEAD itself carries
#       no file changes) → do NOT skip; walk back to find the most recently
#       changed non-empty commit's files and run the gate against those.
#       If no non-empty ancestor is found within 20 commits, refuse to pass.

if git rev-parse --git-dir >/dev/null 2>&1; then
  changed=$( {
    git diff --name-only HEAD~1 HEAD 2>/dev/null
    git diff --name-only 2>/dev/null
    git diff --name-only --cached 2>/dev/null
    git ls-files --others --exclude-standard 2>/dev/null
  } | sort -u | grep -v '^$' || true )

  if [ -z "$changed" ]; then
    # R3-J: Check whether HEAD itself is an empty commit -----------------------
    # An empty commit has a parent but git diff-tree reports no changed files.
    has_parent=false
    if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
      has_parent=true
    fi

    head_files=""
    if "$has_parent"; then
      head_files=$(git diff-tree --no-commit-id --name-only -r HEAD 2>/dev/null || true)
    fi

    if "$has_parent" && [ -z "$head_files" ]; then
      # HEAD is an empty commit — do not skip.  Walk back up to 20 commits to
      # find the last non-empty commit and use its changed files as the verify
      # target.  This ensures an --allow-empty commit never silently passes.
      echo "TaskCompleted: detected empty commit on HEAD; scanning recent history for last real change." >&2
      ancestor_changed=""
      for n in $(seq 1 20); do
        ancestor=$(git rev-parse --verify "HEAD~${n}" 2>/dev/null || true)
        [ -z "$ancestor" ] && break
        parent=$(git rev-parse --verify "HEAD~$((n+1))" 2>/dev/null || true)
        if [ -n "$parent" ]; then
          ancestor_changed=$(git diff-tree --no-commit-id --name-only -r "HEAD~${n}" 2>/dev/null || true)
        else
          # root commit: show all files it introduced
          ancestor_changed=$(git diff-tree --no-commit-id --name-only --root "HEAD~${n}" 2>/dev/null || true)
        fi
        if [ -n "$ancestor_changed" ]; then
          changed="$ancestor_changed"
          break
        fi
      done

      if [ -z "$changed" ]; then
        echo "TaskCompleted: empty commit and no non-empty ancestor found within 20 commits; blocking to be safe." >&2
        exit 2
      fi
      echo "TaskCompleted: using files from last non-empty ancestor for verify gate." >&2
    else
      # Genuine clean tree: no HEAD, or HEAD has real file changes but working
      # tree and index are fully clean.  Safe to skip.
      exit 0
    fi
    # (fall through with $changed populated from ancestor)
  fi

  non_docs=$(echo "$changed" | grep -Ev \
    -e '\.(md|markdown|txt|rst|adoc|png|jpg|jpeg|gif|svg)$' \
    -e '(^|/)(CHANGELOG|LICENSE|NOTICE|AUTHORS|CONTRIBUTING|README)(\..+)?$' \
    || true)
  if [ -z "$non_docs" ]; then
    echo "TaskCompleted: docs-only changes detected; skipping type-check/build gate." >&2
    exit 0
  fi
fi

TMP=$(mktemp -d -t cc-verify.XXXXXX)
trap 'rm -rf "$TMP"; _restore_stash_if_present' EXIT

# -- Stash helpers -----------------------------------------------------------
# Track whether we have stashed, so the EXIT trap can restore on abort.
_STASH_LABEL=""
_restore_stash_if_present() {
  if [ -n "$_STASH_LABEL" ]; then
    # Look for our stash and pop if present.
    if git stash list 2>/dev/null | grep -qF "$_STASH_LABEL"; then
      git stash pop --quiet >/dev/null 2>&1 || \
        echo "WARN: failed to restore baseline stash '$_STASH_LABEL' — recover with 'git stash list' / 'git stash pop'" >&2
    fi
    _STASH_LABEL=""
  fi
}

# Run a command with the working tree stashed to HEAD baseline.
# Args: <output-file> <command...>
# The command is invoked with the working tree at HEAD; output goes to file.
_run_against_baseline() {
  local out="$1"; shift
  _STASH_LABEL="cc-hook-baseline-$$-$(date +%s)"
  if ! git stash push --include-untracked --quiet --message "$_STASH_LABEL" 2>/dev/null; then
    # Stash failed (likely nothing to stash — working tree already clean against HEAD).
    _STASH_LABEL=""
    "$@" >"$out" 2>&1 || true
    return 0
  fi
  # Verify the stash actually landed (push succeeds quietly even with nothing to stash).
  if ! git stash list 2>/dev/null | grep -qF "$_STASH_LABEL"; then
    _STASH_LABEL=""
  fi
  "$@" >"$out" 2>&1 || true
  _restore_stash_if_present
}

# -- Baseline-delta orchestrator ---------------------------------------------
# Compare current-run errors vs baseline-run errors. Block only if new errors.
#
# Args: <label> <error-extractor-fn> <gate-cmd...>
# - error-extractor-fn: function name that reads stdin (the gate output) and emits one
#   normalized error signature per line on stdout.
# - gate-cmd: the command to run for the actual check (e.g., "pnpm tsc --noEmit").
#
# Returns 0 (continue), or exits 2 (block) directly.
_baseline_delta_check() {
  local label="$1"; shift
  local extractor="$1"; shift
  local current_out="$TMP/${label}-current.txt"
  local baseline_out="$TMP/${label}-baseline.txt"

  # Step 1: Run gate on the current working tree.
  local rc=0
  "$@" >"$current_out" 2>&1 || rc=$?
  if [ $rc -eq 0 ]; then
    return 0  # gate passed, nothing to do
  fi

  # Step 2: Capture baseline by stashing and re-running.
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    # Not in a git repo — can't compute baseline. Surface current errors as-is.
    echo "--- $label errors (no git, baseline unavailable) ---" >&2
    tail -10 "$current_out" >&2
    echo "$label gate failed — fix before completing this task" >&2
    exit 2
  fi
  _run_against_baseline "$baseline_out" "$@"

  # Step 3: Extract and diff error signatures.
  local current_sigs="$TMP/${label}-current-sigs.txt"
  local baseline_sigs="$TMP/${label}-baseline-sigs.txt"
  "$extractor" <"$current_out" | sort -u >"$current_sigs"
  "$extractor" <"$baseline_out" | sort -u >"$baseline_sigs"

  # New errors = in current, not in baseline.
  local new_sigs="$TMP/${label}-new-sigs.txt"
  comm -23 "$current_sigs" "$baseline_sigs" >"$new_sigs"

  local new_count baseline_count
  new_count=$(grep -c . "$new_sigs" 2>/dev/null) || new_count=0
  baseline_count=$(grep -c . "$baseline_sigs" 2>/dev/null) || baseline_count=0

  if [ "$new_count" -eq 0 ]; then
    echo "TaskCompleted: $label gate failed but all errors are pre-existing (baseline: $baseline_count); not blocking on unrelated issues." >&2
    return 0
  fi

  echo "--- New $label errors introduced by this task ($new_count of $((baseline_count + new_count)) total) ---" >&2
  head -10 "$new_sigs" >&2
  echo "$label errors introduced — fix before completing this task" >&2
  exit 2
}

# -- Error extractors --------------------------------------------------------
# Each extractor reads stdin (gate output) and emits normalized error signatures.

_extract_mypy_errors() {
  # mypy: "path/to/file.py:LINE: error: message  [code]"
  grep -E '^[^[:space:]].*:[0-9]+:[ ]?(error|warning):' || true
}

_extract_tsc_errors() {
  # tsc: "path/to/file.ts(LINE,COL): error TSXXXX: message"
  grep -E ': error TS[0-9]+:' || true
}

_extract_cargo_errors() {
  # cargo check: "error[E0XXX]: message" + "  --> path:line:col"
  # Pair error+location into one signature.
  awk '
    /^error(\[E[0-9]+\])?:/ { msg=$0; next }
    /^[[:space:]]+--> / && msg { print msg " " $2; msg=""; next }
    /^error:/ { print; next }
  ' || true
}

_extract_pytest_failures() {
  # pytest: "FAILED tests/test_x.py::test_name - reason"
  grep -E '^FAILED ' || true
}

_extract_jest_failures() {
  # jest/vitest: "FAIL tests/x.test.ts > description"
  grep -E '^(FAIL|✗|×) ' || true
}

_extract_swift_errors() {
  # swift build: "path/to/file.swift:LINE:COL: error: message"
  grep -E ':[0-9]+:[0-9]+: error:' || true
}

_extract_xcodebuild_errors() {
  # xcodebuild: "/path/Project.xcodeproj: error: ..." or "/path/file.swift:LINE:COL: error: ..."
  grep -E '(error:|: error )' || true
}

_extract_go_errors() {
  # go build: "path/to/file.go:LINE:COL: message"
  grep -E '^[^[:space:]].*\.go:[0-9]+(:[0-9]+)?:' || true
}

# -- Gate runners (call commands, do not print output) -----------------------
# These produce raw output; the orchestrator handles success/failure semantics.

_gate_pnpm_tsc()      { pnpm tsc --noEmit; }
_gate_pnpm_test()     { pnpm test; }
_gate_cargo_check()   { cargo check; }
_gate_cargo_test() {
  if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run
  else
    cargo test
  fi
}
_gate_mypy()          { python3 -m mypy .; }
_gate_pytest()        { python3 -m pytest; }
_gate_swift_build()   { swift build; }
_gate_swift_test()    { swift test; }
_gate_go_build()      { go build ./...; }
_gate_go_test()       { go test ./...; }

# -- Project-type runners ----------------------------------------------------

run_web() {
  _baseline_delta_check "TypeScript" _extract_tsc_errors _gate_pnpm_tsc
  _baseline_delta_check "JS-tests" _extract_jest_failures _gate_pnpm_test
}

run_rust() {
  _baseline_delta_check "Rust-compile" _extract_cargo_errors _gate_cargo_check
  _baseline_delta_check "Rust-tests" _extract_cargo_errors _gate_cargo_test
}

run_python() {
  if [ -f pyproject.toml ] && grep -q 'mypy\|pyright' pyproject.toml 2>/dev/null; then
    _baseline_delta_check "Python-types" _extract_mypy_errors _gate_mypy
  fi
  _baseline_delta_check "Python-tests" _extract_pytest_failures _gate_pytest
}

run_swift() {
  if [ -f Package.swift ]; then
    _baseline_delta_check "Swift-build" _extract_swift_errors _gate_swift_build
    _baseline_delta_check "Swift-tests" _extract_swift_errors _gate_swift_test
  else
    # Xcode-project fallback. Use first xcodeproj found, dynamic scheme detection.
    local xcproj
    xcproj=$(find . -maxdepth 2 -name "*.xcodeproj" -print -quit 2>/dev/null)
    [ -z "$xcproj" ] && return 0
    local scheme
    scheme=$(xcodebuild -project "$xcproj" -list -json 2>/dev/null \
      | jq -r '.project.schemes[0] // empty' 2>/dev/null)
    if [ -z "$scheme" ]; then
      echo "xcodebuild: no scheme found in $xcproj; skipping iOS build gate" >&2
      return 0
    fi
    _gate_xcodebuild() {
      xcodebuild -project "$xcproj" -scheme "$scheme" \
        -destination 'generic/platform=iOS' -quiet build
    }
    _baseline_delta_check "Xcode-build" _extract_xcodebuild_errors _gate_xcodebuild
  fi
}

run_go() {
  _baseline_delta_check "Go-build" _extract_go_errors _gate_go_build
  _baseline_delta_check "Go-tests" _extract_go_errors _gate_go_test
}

run_tauri() {
  # Web gate first (TypeScript/frontend).
  run_web
  # Rust gate for the src-tauri crate.
  _gate_tauri_cargo_check() { (cd src-tauri && cargo check); }
  _baseline_delta_check "Tauri-Rust" _extract_cargo_errors _gate_tauri_cargo_check
  # Run tests if test targets exist (avoids error when there are none).
  if (cd src-tauri && cargo test --manifest-path Cargo.toml -- --list 2>/dev/null | grep -q 'test'); then
    _gate_tauri_cargo_test() {
      if command -v cargo-nextest >/dev/null 2>&1; then
        (cd src-tauri && cargo nextest run)
      else
        (cd src-tauri && cargo test)
      fi
    }
    _baseline_delta_check "Tauri-Rust-tests" _extract_cargo_errors _gate_tauri_cargo_test
  fi
}

# -- Project-type detection --------------------------------------------------

# Tauri hybrid: both src-tauri/Cargo.toml AND package.json present,
# OR package.json with @tauri-apps/* dependency.
is_tauri=false
if [ -f src-tauri/Cargo.toml ] && [ -f package.json ]; then
  is_tauri=true
elif [ -f package.json ] && jq -e '(.dependencies // {}) + (.devDependencies // {}) | keys[] | select(startswith("@tauri-apps/"))' package.json >/dev/null 2>&1; then
  is_tauri=true
fi

if "$is_tauri"; then
  run_tauri
elif [ -f package.json ]; then
  run_web
elif [ -f Cargo.toml ]; then
  run_rust
elif [ -f pyproject.toml ] || [ -f setup.py ] || [ -f requirements.txt ]; then
  run_python
elif [ -f Package.swift ] || find . -maxdepth 2 -name "*.xcodeproj" -print -quit 2>/dev/null | grep -q .; then
  run_swift
elif [ -f go.mod ]; then
  run_go
fi

exit 0
