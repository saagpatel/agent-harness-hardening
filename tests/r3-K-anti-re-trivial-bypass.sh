#!/usr/bin/env bash
# Inert reproduction: haiku-routing-classifier ANTI_RE trivial bypass
# Demonstrates that prepending an ANTI_RE verb to a read-only research task
# causes the classifier to pass a Sonnet dispatch that should be Haiku.
#
# This is NOT a security control — it's a cost-routing control.
# But it means the classifier can be weaponized to FORCE Sonnet for any
# read-only task by prefixing "write" or another ANTI_RE word.
#
# The risk: a malicious prompt in an automated pipeline could craft Agent
# dispatches that always use Sonnet (bypassing cost enforcement), or
# could force a more capable model for a task the operator intended to
# run cheaply on Haiku.

HOOK="$HOME/.claude/hooks/haiku-routing-classifier.sh"

echo "=== Test 1: PRO_RE only — should BLOCK (force haiku) ==="
INPUT1='{"tool_name":"Agent","tool_input":{"description":"find all files referencing confirm-token","prompt":"Look up which hooks reference the confirm-token directory. List all files.","model":"sonnet","subagent_type":"general-purpose"}}'
echo "$INPUT1" | bash "$HOOK"
echo "EXIT=$?"

echo ""
echo "=== Test 2: PRO_RE + ANTI_RE prefix — should PASS (bypass to Sonnet) ==="
INPUT2='{"tool_name":"Agent","tool_input":{"description":"write a report: find all files referencing confirm-token","prompt":"Write a summary of which hooks reference the confirm-token directory. Find all files.","model":"sonnet","subagent_type":"general-purpose"}}'
echo "$INPUT2" | bash "$HOOK"
echo "EXIT=$?"

echo ""
echo "=== Test 3: Specialist exemption — should PASS unconditionally ==="
INPUT3='{"tool_name":"Agent","tool_input":{"description":"find all issues in this diff","prompt":"find all bugs, list all problems, summarize all findings","model":"sonnet","subagent_type":"code-reviewer"}}'
echo "$INPUT3" | bash "$HOOK"
echo "EXIT=$?"
