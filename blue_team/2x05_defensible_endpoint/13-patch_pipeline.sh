#!/bin/bash
set -uo pipefail

OUT="pipeline_run.json"
TMP_OUT="${OUT}.tmp"
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)

STAGES='[]'
ARTIFACTS='{}'
PIPELINE_STATUS="ok"

STAGE_NUM=0
TOTAL_STAGES=9

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR" "$TMP_OUT"' EXIT

add_stage() {
    local stage="$1"
    local exit_code="$2"
    local duration="$3"
    local stdout_text="$4"
    local stderr_text="$5"
    local status="$6"

    local entry

    entry=$(jq -n \
        --arg stage "$stage" \
        --argjson exit_code "$exit_code" \
        --argjson duration "$duration" \
        --arg stdout "$stdout_text" \
        --arg stderr "$stderr_text" \
        --arg status "$status" \
        '{
            stage: $stage,
            exit_code: $exit_code,
            duration_seconds: $duration,
            stdout: $stdout,
            stderr: $stderr,
            status: $status
        }')

    STAGES=$(printf '%s\n' "$STAGES" |
        jq --argjson entry "$entry" '. + [$entry]')
}

add_artifact() {
    local stage="$1"
    local artifact="$2"

    if [ -n "$artifact" ] && [ -f "$artifact" ]; then
        ARTIFACTS=$(printf '%s\n' "$ARTIFACTS" |
            jq \
                --arg stage "$stage" \
                --arg artifact "$artifact" \
                '. + {($stage): $artifact}')
    fi
}

run_stage() {
    local script="$1"
    local artifact="$2"
    local timeout_seconds="${3:-0}"

    local stdout_file
    local stderr_file
    local stdout_text
    local stderr_text
    local start_ns
    local end_ns
    local duration
    local exit_code

    STAGE_NUM=$((STAGE_NUM + 1))

    stdout_file="$TMP_DIR/stage-${STAGE_NUM}.stdout"
    stderr_file="$TMP_DIR/stage-${STAGE_NUM}.stderr"

    start_ns=$(date +%s%N)

    if [ "$timeout_seconds" -gt 0 ]; then
        timeout "$timeout_seconds" "./$script" \
            >"$stdout_file" 2>"$stderr_file"
        exit_code=$?
    else
        "./$script" \
            >"$stdout_file" 2>"$stderr_file"
        exit_code=$?
    fi

    end_ns=$(date +%s%N)

    duration=$(awk \
        -v start="$start_ns" \
        -v end="$end_ns" \
        'BEGIN {printf "%.1f", (end-start)/1000000000}')

    stdout_text=$(cat "$stdout_file")
    stderr_text=$(cat "$stderr_file")

    if [ "$exit_code" -eq 0 ]; then
        printf "[%d/%d] %-30s OK  (%ss)\n" \
            "$STAGE_NUM" \
            "$TOTAL_STAGES" \
            "$script" \
            "$duration"

        add_stage \
            "$script" \
            "$exit_code" \
            "$duration" \
            "$stdout_text" \
            "$stderr_text" \
            "ok"

        add_artifact "$script" "$artifact"

        return 0
    fi

    if [ "$exit_code" -eq 124 ]; then
        printf "[%d/%d] %-30s FAILED (timeout)\n" \
            "$STAGE_NUM" \
            "$TOTAL_STAGES" \
            "$script"
    else
        printf "[%d/%d] %-30s FAILED (exit %d)\n" \
            "$STAGE_NUM" \
            "$TOTAL_STAGES" \
            "$script" \
            "$exit_code"
    fi

    add_stage \
        "$script" \
        "$exit_code" \
        "$duration" \
        "$stdout_text" \
        "$stderr_text" \
        "failed"

    return "$exit_code"
}

run_window_check() {
    local script="11-maintenance_window.sh"

    local stdout_file
    local stderr_file
    local stdout_text
    local stderr_text
    local start_ns
    local end_ns
    local duration
    local exit_code
    local status
    local description

    STAGE_NUM=$((STAGE_NUM + 1))

    stdout_file="$TMP_DIR/window.stdout"
    stderr_file="$TMP_DIR/window.stderr"

    start_ns=$(date +%s%N)

    "./$script" --check \
        >"$stdout_file" 2>"$stderr_file"

    exit_code=$?

    end_ns=$(date +%s%N)

    duration=$(awk \
        -v start="$start_ns" \
        -v end="$end_ns" \
        'BEGIN {printf "%.1f", (end-start)/1000000000}')

    stdout_text=$(cat "$stdout_file")
    stderr_text=$(cat "$stderr_file")

    case "$exit_code" in
        0)
            status="ok"
            description="standard or extended window active"
            ;;

        10)
            if [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
                status="ok"
                description="emergency window override active"
            else
                status="deferred"
                description="emergency window requires MEDDEFENSE_EMERGENCY=1"
            fi
            ;;

        20)
            status="deferred"
            description="outside maintenance window"
            ;;

        *)
            status="failed"
            description="maintenance window check failed"
            ;;
    esac

    printf "[%d/%d] %-30s %s  (%s)\n" \
        "$STAGE_NUM" \
        "$TOTAL_STAGES" \
        "$script" \
        "$(printf '%s' "$status" | tr '[:lower:]' '[:upper:]')" \
        "$description"

    add_stage \
        "$script" \
        "$exit_code" \
        "$duration" \
        "$stdout_text" \
        "$stderr_text" \
        "$status"

    add_artifact \
        "$script" \
        "maintenance_window.json"

    return "$exit_code"
}

add_skipped_stage() {
    local script="$1"
    local reason="$2"

    STAGE_NUM=$((STAGE_NUM + 1))

    printf "[%d/%d] %-30s SKIPPED (%s)\n" \
        "$STAGE_NUM" \
        "$TOTAL_STAGES" \
        "$script" \
        "$reason"

    add_stage \
        "$script" \
        0 \
        0 \
        "" \
        "" \
        "skipped"
}

write_report() {
    local finished_at
    local total_duration

    finished_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    total_duration=$(printf '%s\n' "$STAGES" |
        jq '[.[].duration_seconds] | add // 0')

    jq -n \
        --arg started "$STARTED_AT" \
        --arg finished "$finished_at" \
        --arg hostname "$HOSTNAME" \
        --arg status "$PIPELINE_STATUS" \
        --argjson stages "$STAGES" \
        --argjson artifacts "$ARTIFACTS" \
        '{
            started_at: $started,
            finished_at: $finished,
            hostname: $hostname,
            pipeline_status: $status,
            stages: $stages,
            artifacts: $artifacts
        }' > "$TMP_OUT"

    mv "$TMP_OUT" "$OUT"

    echo "PIPELINE: $PIPELINE_STATUS"
    echo "Duration: ${total_duration}s"
    echo "Report saved to: $OUT"
}

# ------------------------------------------------------------
# 1. Vulnerability inventory
# Timeout prevents an indefinitely hanging inventory operation.
# ------------------------------------------------------------
if ! run_stage \
    "0-vuln_inventory.sh" \
    "vulnerability_inventory.json" \
    300; then

    PIPELINE_STATUS="failed"
    write_report
    exit 1
fi

# ------------------------------------------------------------
# 2. Service dependency map
# ------------------------------------------------------------
if ! run_stage \
    "1-service_deps.sh" \
    "service_dependency_map.json"; then

    PIPELINE_STATUS="failed"
    write_report
    exit 1
fi

# ------------------------------------------------------------
# 3. Pre-patch snapshot
# ------------------------------------------------------------
if ! run_stage \
    "2-pre_patch_snapshot.sh" \
    "pre_patch_state.json"; then

    PIPELINE_STATUS="failed"
    write_report
    exit 1
fi

# ------------------------------------------------------------
# 4. Patch plan
# ------------------------------------------------------------
if ! run_stage \
    "3-patch_plan.sh" \
    "patch_plan.json"; then

    PIPELINE_STATUS="failed"
    write_report
    exit 1
fi

# ------------------------------------------------------------
# 5. Maintenance window
# Required:
# 11-maintenance_window.sh --check
#
# Exit 0  = standard/extended window
# Exit 10 = emergency only
# Exit 20 = outside all windows
# ------------------------------------------------------------
run_window_check
WINDOW_EXIT=$?

case "$WINDOW_EXIT" in

    0)
        # Normal maintenance window.
        ;;

    10)
        if [ "${MEDDEFENSE_EMERGENCY:-0}" != "1" ]; then
            PIPELINE_STATUS="deferred"
        fi
        ;;

    20)
        # Task 13 requirement:
        # out of window => deferred unless an emergency override
        # permits emergency execution.
        if [ "${MEDDEFENSE_EMERGENCY:-0}" != "1" ]; then
            PIPELINE_STATUS="deferred"
        else
            PIPELINE_STATUS="deferred"
        fi
        ;;

    *)
        PIPELINE_STATUS="failed"
        write_report
        exit 1
        ;;
esac

# ------------------------------------------------------------
# Deferred:
# skip stages 4-patch_execute through 6-config_drift.
# ------------------------------------------------------------
if [ "$PIPELINE_STATUS" = "deferred" ]; then

    add_skipped_stage \
        "4-patch_execute.sh" \
        "maintenance window unavailable"

    add_skipped_stage \
        "5-post_patch_validate.sh" \
        "patch execution deferred"

    add_skipped_stage \
        "6-config_drift.sh" \
        "patch execution deferred"

else

    # --------------------------------------------------------
    # 6. Execute patches
    #
    # Idempotency of actual package installation belongs to
    # 4-patch_execute.sh: already-installed upgrades must not
    # be applied again.
    # --------------------------------------------------------
    if ! run_stage \
        "4-patch_execute.sh" \
        "patch_execution_log.json"; then

        PIPELINE_STATUS="failed"
        write_report
        exit 1
    fi

    # --------------------------------------------------------
    # 7. Post-patch validation
    # --------------------------------------------------------
    if ! run_stage \
        "5-post_patch_validate.sh" \
        "post_patch_validation.json"; then

        PIPELINE_STATUS="failed"
        write_report
        exit 1
    fi

    # --------------------------------------------------------
    # 8. Configuration drift
    # --------------------------------------------------------
    if ! run_stage \
        "6-config_drift.sh" \
        "config_drift.json"; then

        PIPELINE_STATUS="failed"
        write_report
        exit 1
    fi
fi

# ------------------------------------------------------------
# 9. Change log
# ------------------------------------------------------------
if ! run_stage \
    "12-change_log.sh" \
    "patch_change_log.json"; then

    PIPELINE_STATUS="failed"
    write_report
    exit 1
fi

write_report

# Exit 0 on ok or deferred.
# Exit 1 on any stage failure.
exit 0
