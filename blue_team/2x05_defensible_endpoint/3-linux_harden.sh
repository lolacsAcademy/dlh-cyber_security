#!/bin/bash
# Log path: capstone/exec/linux_harden.log
# stdout
set -uo pipefail

TARGET_STATE="capstone/target_state.json"
BASELINE="capstone/baseline/baseline_linux.json"

EXEC_DIR="capstone/exec"
LOG="$EXEC_DIR/linux_harden.log"
OUT="$EXEC_DIR/linux_harden.json"
TMP_OUT="${OUT}.tmp"

MODE="${1:-}"

# Existing hardening components.
# Paths may be overridden with environment variables if your files differ.
SSH_SCRIPT="${SSH_HARDEN_SCRIPT:-./ssh_harden.sh}"
SYSCTL_SCRIPT="${SYSCTL_HARDEN_SCRIPT:-./sysctl_harden.sh}"
PERMISSION_SCRIPT="${PERMISSION_HARDEN_SCRIPT:-./permission_sweep.sh}"
SERVICE_SCRIPT="${SERVICE_HARDEN_SCRIPT:-./service_minimization.sh}"
PAM_SCRIPT="${PAM_HARDEN_SCRIPT:-./pam_harden.sh}"
APPARMOR_SCRIPT="${APPARMOR_HARDEN_SCRIPT:-./apparmor_enforce.sh}"
AUDITD_SCRIPT="${AUDITD_HARDEN_SCRIPT:-./auditd_deploy.sh}"

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

for cmd in jq lynis hostname date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

if [ ! -s "$TARGET_STATE" ]; then
    echo "ERROR: missing target state: $TARGET_STATE" >&2
    exit 2
fi

if ! jq empty "$TARGET_STATE" >/dev/null 2>&1; then
    echo "ERROR: corrupted target_state.json" >&2
    exit 2
fi

if [ ! -s "$BASELINE" ]; then
    echo "ERROR: missing baseline: $BASELINE" >&2
    exit 2
fi

if ! jq empty "$BASELINE" >/dev/null 2>&1; then
    echo "ERROR: corrupted baseline_linux.json" >&2
    exit 2
fi

mkdir -p "$EXEC_DIR"

# Target-state Linux Lynis requirement.
LYNIS_TARGET=$(
    jq -r '
        .controls[]
        | select(.id == "LNX-LYNIS-01")
        | .expected_value
    ' "$TARGET_STATE"
)

if ! [[ "$LYNIS_TARGET" =~ ^[0-9]+$ ]]; then
    echo "ERROR: LNX-LYNIS-01 target missing or invalid" >&2
    exit 2
fi

LYNIS_BEFORE=$(
    jq -r '.hardening_index' "$BASELINE"
)

if ! [[ "$LYNIS_BEFORE" =~ ^[0-9]+$ ]]; then
    echo "ERROR: baseline hardening_index invalid" >&2
    exit 2
fi

# Deterministic hardening order.
STEP_NAMES=(
    "SSH hardening"
    "sysctl hardening"
    "permission sweep"
    "service minimization"
    "PAM configuration"
    "AppArmor enforcement"
    "auditd deployment"
)

STEP_SCRIPTS=(
    "$SSH_SCRIPT"
    "$SYSCTL_SCRIPT"
    "$PERMISSION_SCRIPT"
    "$SERVICE_SCRIPT"
    "$PAM_SCRIPT"
    "$APPARMOR_SCRIPT"
    "$AUDITD_SCRIPT"
)

CONTROLS_TOUCHED='[
    "LNX-SSH-01",
    "LNX-SSH-02",
    "LNX-SYSCTL-01",
    "LNX-SYSCTL-02",
    "LNX-AUDITD-01",
    "LNX-APPARMOR-01",
    "LNX-LYNIS-01",
    "TEL-LNX-01",
    "TEL-LNX-02"
]'

echo "Linux hardening orchestration"
echo "Target Lynis Hardening Index: $LYNIS_TARGET"

# ------------------------------------------------------------
# SAFE DEFAULT
# ------------------------------------------------------------
if [ "$MODE" != "--apply" ]; then
    echo
    echo "SAFE MODE: no hardening changes will be applied."
    echo

    MISSING=0

    for index in "${!STEP_SCRIPTS[@]}"; do
        script="${STEP_SCRIPTS[$index]}"
        name="${STEP_NAMES[$index]}"

        if [ -f "$script" ]; then
            echo "[OK] $name -> $script"
        else
            echo "[MISSING] $name -> $script"
            MISSING=1
        fi
    done

    echo
    echo "To perform real hardening:"
    echo "$0 --apply"

    if [ "$MISSING" -ne 0 ]; then
        exit 2
    fi

    exit 0
fi

# ------------------------------------------------------------
# APPLY MODE
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --apply requires root privileges" >&2
    exit 2
fi

for script in "${STEP_SCRIPTS[@]}"; do
    if [ ! -f "$script" ]; then
        echo "ERROR: hardening component missing: $script" >&2
        exit 2
    fi

    if [ ! -x "$script" ]; then
        echo "ERROR: hardening component not executable: $script" >&2
        exit 2
    fi
done

: > "$LOG"

STEPS='[]'
ALL_STEPS_OK=true

run_step() {
    local name="$1"
    local script="$2"

    local started
    local finished
    local duration
    local exit_code
    local output
    local changed
    local entry

    started=$(date +%s)

    {
        echo "===== $name ====="
        echo "script: $script"
    } >> "$LOG"

    set +e
    output=$("$script" 2>&1)
    exit_code=$?
    set -e

    printf '%s\n' "$output" >> "$LOG"

    finished=$(date +%s)
    duration=$((finished - started))

    changed=false

    if printf '%s\n' "$output" |
        grep -Eqi 'changed|modified|updated|applied|configured|enabled'; then
        changed=true
    fi

    entry=$(
        jq -n \
            --arg name "$name" \
            --arg script_path "$script" \
            --argjson exit_code "$exit_code" \
            --argjson duration "$duration" \
            --argjson changed "$changed" \
            '{
                name: $name,
                script_path: $script_path,
                exit_code: $exit_code,
                duration_seconds: $duration,
                changed: $changed
            }'
    )

    STEPS=$(
        printf '%s\n' "$STEPS" |
            jq --argjson entry "$entry" '. + [$entry]'
    )

    printf '[%s] %s (exit=%s, %ss)\n' \
        "$name" \
        "$([ "$exit_code" -eq 0 ] && echo OK || echo FAILED)" \
        "$exit_code" \
        "$duration"

    if [ "$exit_code" -ne 0 ]; then
        ALL_STEPS_OK=false
        return 1
    fi

    return 0
}

# Required deterministic order.
for index in "${!STEP_SCRIPTS[@]}"; do
    if ! run_step \
        "${STEP_NAMES[$index]}" \
        "${STEP_SCRIPTS[$index]}"; then

        break
    fi
done

# ------------------------------------------------------------
# Post-hardening Lynis audit
# ------------------------------------------------------------
LYNIS_AFTER=0
LYNIS_LOG="$EXEC_DIR/lynis_after.log"

if [ "$ALL_STEPS_OK" = true ]; then
    if lynis audit system --quick --no-colors > "$LYNIS_LOG" 2>&1; then
        LYNIS_AFTER=$(
            grep -Ei 'Hardening index' "$LYNIS_LOG" |
                tail -n 1 |
                grep -Eo '[0-9]+' |
                head -n 1 || true
        )

        if ! [[ "$LYNIS_AFTER" =~ ^[0-9]+$ ]]; then
            LYNIS_AFTER=0
            ALL_STEPS_OK=false
        fi
    else
        ALL_STEPS_OK=false
    fi
fi

INDEX_DELTA=$((LYNIS_AFTER - LYNIS_BEFORE))

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VALUE=$(hostname)

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VALUE" \
    --argjson steps "$STEPS" \
    --argjson lynis_before "$LYNIS_BEFORE" \
    --argjson lynis_after "$LYNIS_AFTER" \
    --argjson index_delta "$INDEX_DELTA" \
    --argjson controls_touched "$CONTROLS_TOUCHED" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        steps: $steps,
        lynis_before: $lynis_before,
        lynis_after: $lynis_after,
        index_delta: $index_delta,
        controls_touched: $controls_touched
    }' > "$TMP_OUT"

if ! jq empty "$TMP_OUT" >/dev/null 2>&1; then
    rm -f "$TMP_OUT"
    echo "ERROR: invalid linux_harden.json generated" >&2
    exit 1
fi

mv "$TMP_OUT" "$OUT"

echo "Lynis before: $LYNIS_BEFORE"
echo "Lynis after:  $LYNIS_AFTER"
echo "Target:       $LYNIS_TARGET"
echo "Evidence:     $OUT"
echo "Log:          $LOG"

if [ "$ALL_STEPS_OK" != true ]; then
    echo "ERROR: one or more hardening steps failed" >&2
    exit 1
fi

if [ "$LYNIS_AFTER" -lt "$LYNIS_TARGET" ]; then
    echo "ERROR: Lynis target was not reached" >&2
    exit 1
fi

exit 0
