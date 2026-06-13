#!/usr/bin/env bash
# PostToolUse: Log mutating MCP tool calls to ~/.claude/logs/mcp-mutations.jsonl
#
# FIX R3-Jb: audit blind spot.
# The old approach used a mutating-verb allowlist (opt-in to log) which silently
# dropped unknown tools. New approach: log EVERYTHING that is not on an explicit,
# anchored read-only allowlist. Unknown tools → logged. Read-only tools → skipped.
#
# Read-only allowlist criteria: the tool performs no persistent side-effects
# (returns data, enumerates state, or reads content). If in doubt, LOG IT.
set -euo pipefail

INPUT=$(cat)

TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ -z "$TOOL" ] && exit 0

# Lowercase for case-insensitive matching
TOOL_LOWER=$(echo "$TOOL" | tr '[:upper:]' '[:lower:]')

# R3-Jb: Explicit read-only allowlist (anchored full-name match or suffix/prefix).
# Tools on this list are SKIPPED (not logged).  Everything else is logged.
#
# Rules for adding here:
#   - Must be provably read-only (no DB writes, no state mutations, no sends).
#   - Must be an exact tool name OR a suffix/prefix that only matches read-only tools.
#   - When in doubt, do NOT add — let it log.
#
# Covered safe patterns (all anchored to prevent substring false-positives):
#   *_list, *_get, get_*, read_*, search_*, *_status, *_show, *_health,
#   *_tail, *_stats, recall, health, status, export_bridge_markdown (read-only render),
#   audit_tail (read-only log reader)

is_readonly() {
  local t="$1"
  # Exact matches for known safe singletons
  case "$t" in
    recall|health|status|audit_tail|export_bridge_markdown|\
    personal_ops_status|personal_ops_worklist|inbox_status|\
    send_window_status|calendar_status|github_status|drive_status|\
    inbox_classified|agent_performance_summary|coordination_lanes_analytics|\
    portfolio_health|notion_project_status|operator_inbox|\
    outbound_lane_readiness_verify|planning_recommendation_verify|\
    calendar_lane_readiness_verify|mcp_security_posture|\
    personal_ops_doctor|end_of_day_digest|meeting_contact_brief|\
    notification_feed|ai_activity_summary|ai_context_recall|\
    recall_stats|cost_today|cost_session|cost_monthly_trend|\
    cost_top_projects|cost_alert_thresholds_check|\
    ctx_stats|ctx_doctor|ctx_search)
      return 0 ;;
  esac

  # Suffix patterns: *_list, *_get, *_tail, *_status, *_health, *_show,
  #                  *_pending, *_recent, *_upcoming, *_free_time,
  #                  *_summary, *_next, *_hygiene, *_tuning, *_closure,
  #                  *_backlog, *_analytics, *_verify, *_readiness_verify
  case "$t" in
    *_list|*_get|*_tail|*_status|*_health|*_show|\
    *_pending|*_recent|*_upcoming|*_free_time|\
    *_summary|*_next|*_hygiene|*_tuning|*_closure|\
    *_backlog|*_analytics)
      return 0 ;;
  esac

  # Prefix patterns: get_*, read_*, search_*, list_*
  case "$t" in
    get_*|read_*|search_*|list_*)
      return 0 ;;
  esac

  # Not matched → mutating (or unknown) → log it
  return 1
}

if is_readonly "$TOOL_LOWER"; then
  exit 0
fi

# Everything else gets logged — including previously-missed tools:
#   mark_shipped_processed, pick_up_handoff, clear_handoff, save_snapshot,
#   confirm_shipped_sync, log_activity, update_section, record_cost,
#   create_handoff, sync_from_file,
#   engraph: append, archive, move_note, migrate_apply, migrate_undo,
#            create, delete, edit, rewrite, edit_frontmatter, update_metadata,
#            unarchive, reindex_file
#   personal-ops: mail_draft_*, approval_request_*, task_suggestion_create,
#                 planning_recommendation_create, draft_followup
#   Cloudflare/Vercel: *_create, *_delete, *_deploy, *_edit, ...

LOG_DIR="${MCP_AUDIT_LOG_DIR:-$HOME/.claude/logs}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/mcp-mutations.jsonl"

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)
[ -z "$CWD" ] && CWD=$(pwd)

jq -nc \
  --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg tool "$TOOL" \
  --arg project "$CWD" \
  '{"timestamp": $ts, "tool": $tool, "project": $project}' >> "$LOG_FILE"

exit 0
