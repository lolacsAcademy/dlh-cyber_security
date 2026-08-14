#!/bin/bash
set -uo pipefail

OUT="pipeline_run.json"
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)

STAGES="[]"
ARTIFACTS="{}"
PIPELINE_STATUS="ok"
STAGE_NUM=0
TOTAL_STAGES=9

run_stage() {
    local script="$1"
    local args="${2:-}"
    local artifact="$3"
    STAGE_NUM=$((STAGE_NUM+1))

    local start_ts end_ts duration stdout_out stderr_out exit_code
    start_ts=$(date +%s.%N)

    stdout_out=$(eval "./$script $args" 2>/tmp/stage_stderr.txt)
    exit_code=$?
    stderr_out=$(cat /tmp/stage_stderr.txt)

    end_ts=$(date +%s.%N)
    duration=$(awk -v a="$start_ts" -v b="$end_ts" 'BEGIN{printf "%.1f", b-a}')

    local status="OK"
    [ $exit_code -ne 0 ] && status="FAILED"

    printf "[%d/%d] %-30s %s  (%ss)\n" "$STAGE_NUM" "$TOTAL_STAGES" "$script" "$status" "$duration"

    local stdout_tail stderr_tail
    stdout_tail=$(echo "$stdout_out" | tail -5)
    stderr_tail=$(echo "$stderr_out" | tail -5)

    local entry
    entry=$(jq -n --arg s "$script" --argjson ec "$exit_code" --argjson dur "$duration" \
        --arg sout "$stdout_tail" --arg serr "$stderr_tail" \
        '{stage:$s, exit_code:$ec, duration_seconds:$dur, stdout_tail:$sout, stderr_tail:$serr}')
    STAGES=$(echo "$STAGES" | jq --argjson e "$entry" '. + [$e]')

    if [ -n "$artifact" ] && [ -f "$artifact" ]; then
        ARTIFACTS=$(echo "$ARTIFACTS" | jq --arg k "$script" --arg v "$artifact" '. + {($k): $v}')
    fi

    return $exit_code
}

STAGE_NUM=$((STAGE_NUM+1))
if [ -f "vulnerability_inventory.json" ] && [ $(( $(date +%s) - $(stat -c %Y vulnerability_inventory.json) )) -lt 3600 ]; then
    printf "[%d/%d] %-30s SKIP (fresh artifact, <1h old)\n" "$STAGE_NUM" "$TOTAL_STAGES" "0-vuln_inventory.sh"
    ARTIFACTS=$(echo "$ARTIFACTS" | jq '. + {"0-vuln_inventory.sh": "vulnerability_inventory.json"}')
    entry=$(jq -n '{stage:"0-vuln_inventory.sh", exit_code:0, duration_seconds:0, stdout_tail:"skipped: fresh artifact", stderr_tail:""}')
    STAGES=$(echo "$STAGES" | jq --argjson e "$entry" '. + [$e]')
else
    STAGE_NUM=$((STAGE_NUM-1))
    run_stage "0-vuln_inventory.sh" "" "vulnerability_inventory.json" || PIPELINE_STATUS="failed"
fi

if [ "$PIPELINE_STATUS" = "ok" ]; then
    run_stage "1-service_deps.sh" "" "service_dependency_map.json" || PIPELINE_STATUS="failed"
fi
if [ "$PIPELINE_STATUS" = "ok" ]; then
    run_stage "2-pre_patch_snapshot.sh" "" "pre_patch_state.json" || PIPELINE_STATUS="failed"
fi
if [ "$PIPELINE_STATUS" = "ok" ]; then
    run_stage "3-patch_plan.sh" "" "patch_plan.json" || PIPELINE_STATUS="failed"
fi

WINDOW_EXIT=0
if [ "$PIPELINE_STATUS" = "ok" ]; then
    STAGE_NUM=$((STAGE_NUM+1))
    start_ts=$(date +%s.%N)
    window_stdout=$(./11-maintenance_window.sh --check 2>/tmp/window_stderr.txt)
    WINDOW_EXIT=$?
    window_stderr=$(cat /tmp/window_stderr.txt)
    end_ts=$(date +%s.%N)
    duration=$(awk -v a="$start_ts" -v b="$end_ts" 'BEGIN{printf "%.1f", b-a}')

    window_desc="out of window"
    [ "$WINDOW_EXIT" -eq 0 ] && window_desc="standard window active"
    [ "$WINDOW_EXIT" -eq 10 ] && window_desc="emergency window"

    printf "[%d/%d] %-30s OK  (%s)\n" "$STAGE_NUM" "$TOTAL_STAGES" "11-maintenance_window.sh" "$window_desc"

    entry=$(jq -n --arg s "11-maintenance_window.sh" --argjson ec "$WINDOW_EXIT" --argjson dur "$duration" \
        --arg sout "$window_stdout" --arg serr "$window_stderr" \
        '{stage:$s, exit_code:$ec, duration_seconds:$dur, stdout_tail:$sout, stderr_tail:$serr}')
    STAGES=$(echo "$STAGES" | jq --argjson e "$entry" '. + [$e]')
    ARTIFACTS=$(echo "$ARTIFACTS" | jq '. + {"11-maintenance_window.sh": "maintenance_window.json"}')
fi

SKIP_EXEC="no"
if { [ "$WINDOW_EXIT" -eq 20 ] || [ "$WINDOW_EXIT" -eq 10 ]; } && [ "${MEDDEFENSE_EMERGENCY:-0}" != "1" ]; then
    SKIP_EXEC="yes"
    PIPELINE_STATUS="deferred"
fi

if [ "$PIPELINE_STATUS" != "failed" ] && [ "$SKIP_EXEC" = "no" ]; then
    run_stage "4-patch_execute.sh" "" "patch_execution_log.json" || PIPELINE_STATUS="failed"
    if [ "$PIPELINE_STATUS" != "failed" ]; then
        run_stage "5-post_patch_validate.sh" "" "post_patch_validation.json" || PIPELINE_STATUS="failed"
    fi
    if [ "$PIPELINE_STATUS" != "failed" ]; then
        run_stage "6-config_drift.sh" "" "config_drift.json" || PIPELINE_STATUS="failed"
    fi
fi

if [ "$SKIP_EXEC" = "yes" ]; then
    echo "[*] Outside maintenance window and MEDDEFENSE_EMERGENCY not set — skipping stages 4-6"
fi

if [ "$PIPELINE_STATUS" != "failed" ]; then
    run_stage "12-change_log.sh" "" "patch_change_log.json" || PIPELINE_STATUS="failed"
fi

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TOTAL_DURATION=$(echo "$STAGES" | jq '[.[].duration_seconds | tonumber] | add')

jq -n --arg started "$STARTED_AT" --arg finished "$FINISHED_AT" --arg host "$HOSTNAME" \
    --arg status "$PIPELINE_STATUS" --argjson stages "$STAGES" --argjson artifacts "$ARTIFACTS" \
    '{started_at:$started, finished_at:$finished, hostname:$host, pipeline_status:$status, stages:$stages, artifacts:$artifacts}' > "$OUT"

echo "PIPELINE: $PIPELINE_STATUS"
echo "Duration: ${TOTAL_DURATION}s"
echo "Report saved to: $OUT"

if [ "$PIPELINE_STATUS" = "failed" ]; then
    exit 1
fi
exit 0
