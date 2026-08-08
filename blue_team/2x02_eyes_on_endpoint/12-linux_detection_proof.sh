#!/bin/bash
# name: 12-linux_detection_proof.sh
# purpose: Linux Detection Proof
# author: analyst

set -e
set -u
set -o pipefail

BASE_DIR="$(dirname "$0")"
GROUND_TRUTH_FILE="$BASE_DIR/linux_attack_log.json"
OUTPUT_FILE="$BASE_DIR/linux_detection_matrix.json"
WINDOW_SECONDS=30

if [ ! -f "$GROUND_TRUTH_FILE" ]; then
    echo "ERROR: linux_attack_log.json not found."
    exit 1
fi

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required."
    exit 1
}

command -v ausearch >/dev/null 2>&1 || {
    echo "ERROR: ausearch is required."
    exit 1
}

ACTIONS_COUNT=$(jq '.actions | length' "$GROUND_TRUTH_FILE")

echo "[*] Loading ground truth ($ACTIONS_COUNT actions)..."
echo "[*] Searching telemetry..."

DETECTIONS="[]"
CAPTURED=0
MULTI_SOURCE=0

add_detection() {
    local NUMBER="$1"
    local SOURCE="$2"
    local KEY="$3"
    local DETAIL="$4"
    local FIELDS="$5"

    DETECTIONS=$(printf '%s' "$DETECTIONS" | jq \
        --argjson number "$NUMBER" \
        --arg source "$SOURCE" \
        --arg key "$KEY" \
        --arg detail "$DETAIL" \
        --arg fields "$FIELDS" \
        '. + [{
            action_number: $number,
            source: $source,
            audit_key: $key,
            detail: $detail,
            key_fields: $fields,
            status: "CAPTURED"
        }]')
}

time_only() {
    date -d "@$1" '+%H:%M:%S'
}

search_text_log() {
    local FILE="$1"
    local ACTION_EPOCH="$2"

    [ -f "$FILE" ] || return 0

    local START=$((ACTION_EPOCH - WINDOW_SECONDS))
    local END=$((ACTION_EPOCH + WINDOW_SECONDS))

    awk -v start="$START" -v end="$END" '
    {
        if (match($0, /[0-9]{2}\/[0-9]{2}\/[0-9]{4}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
            value=substr($0, RSTART, RLENGTH)

            command="date -u -d \"" value "\" +%s 2>/dev/null"
            command | getline epoch
            close(command)

            if (epoch >= start && epoch <= end)
                print
        }
    }' "$FILE"
}

ALL_AUDIT=$(sudo ausearch -ts today 2>/dev/null || true)

while IFS= read -r ACTION; do

    NUMBER=$(printf '%s' "$ACTION" | jq -r '.action_number')
    DESCRIPTION=$(printf '%s' "$ACTION" | jq -r '.description')
    TIMESTAMP=$(printf '%s' "$ACTION" | jq -r '.timestamp')

    ACTION_EPOCH=$(date -u -d "$TIMESTAMP" +%s)

    START_EPOCH=$((ACTION_EPOCH - WINDOW_SECONDS))
    END_EPOCH=$((ACTION_EPOCH + WINDOW_SECONDS))

    WINDOW_AUDIT=$(printf '%s\n' "$ALL_AUDIT" | awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
    {
        if (match($0, /audit\([0-9]+\./)) {
            ts_str = substr($0, RSTART+6, RLENGTH-7)
            split(ts_str, a, ".")
            ts = a[1]
            if (ts >= s && ts <= e) print
        } else {
            print
        }
    }')

    AUTH_WINDOW=""
    SYSLOG_WINDOW=""

    if [ -f /var/log/auth.log ]; then
        AUTH_WINDOW=$(search_text_log "/var/log/auth.log" "$ACTION_EPOCH")
    fi

    if [ -f /var/log/syslog ]; then
        SYSLOG_WINDOW=$(search_text_log "/var/log/syslog" "$ACTION_EPOCH")
    fi

    BEFORE=$(printf '%s' "$DETECTIONS" | jq 'length')

    case "$DESCRIPTION" in

        "Create user testattacker")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE 'testattacker|ADD_USER|USER_ACCT|useradd|key=identity'; then
                add_detection "$NUMBER" "auditd" "identity" "Full" "uid; auid; exe; comm; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE 'testattacker|useradd|new user|new account'; then
                add_detection "$NUMBER" "auth.log" "useradd" "Full" "user; account; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE 'testattacker|useradd|new user|new account'; then
                add_detection "$NUMBER" "syslog" "useradd" "Full" "user; account; timestamp"
            fi
            ;;

        "Modify sudoers")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE 'key=sudoers|/etc/sudoers.d|backdoor'; then
                add_detection "$NUMBER" "auditd" "sudoers" "Full" "name; exe; uid; auid; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE 'sudoers|backdoor|sudo'; then
                add_detection "$NUMBER" "auth.log" "sudoers" "Full" "user; command; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE 'sudoers|backdoor|sudo'; then
                add_detection "$NUMBER" "syslog" "sudoers" "Full" "user; command; timestamp"
            fi
            ;;

        "Execute binary from /tmp")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE 'key=process_exec|suspicious_bin|/tmp/suspicious_bin'; then
                add_detection "$NUMBER" "auditd" "process_exec" "Full" "exe; pid; ppid; uid; auid; comm; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE 'suspicious_bin|/tmp'; then
                add_detection "$NUMBER" "auth.log" "process_exec" "Full" "user; command; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE 'suspicious_bin|/tmp'; then
                add_detection "$NUMBER" "syslog" "process_exec" "Full" "user; command; timestamp"
            fi
            ;;

        "Attempt reverse shell to localhost")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE 'key=network_connect|127\.0\.0\.1|4444'; then
                add_detection "$NUMBER" "auditd" "network_connect" "Full" "exe; pid; uid; auid; comm; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE '127\.0\.0\.1|4444|network|connect'; then
                add_detection "$NUMBER" "auth.log" "network_connect" "Full" "user; command; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE '127\.0\.0\.1|4444|network|connect'; then
                add_detection "$NUMBER" "syslog" "network_connect" "Full" "user; command; timestamp"
            fi
            ;;

        "Modify crontab")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE 'key=cron_persist|/etc/cron.d|persistence_test|beacon\.sh'; then
                add_detection "$NUMBER" "auditd" "cron_persist" "Full" "name; exe; uid; auid; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE 'cron|persistence_test|beacon\.sh'; then
                add_detection "$NUMBER" "auth.log" "cron_persist" "Full" "user; command; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE 'cron|persistence_test|beacon\.sh'; then
                add_detection "$NUMBER" "syslog" "cron_persist" "Full" "user; command; timestamp"
            fi
            ;;

        "Access sensitive file /etc/shadow")
            if printf '%s\n' "$WINDOW_AUDIT" | grep -qiE '/etc/shadow|key=identity'; then
                add_detection "$NUMBER" "auditd" "identity" "Full" "name; exe; uid; auid; success"
            fi
            if printf '%s\n' "$AUTH_WINDOW" | grep -qiE '/etc/shadow'; then
                add_detection "$NUMBER" "auth.log" "identity" "Full" "user; file; timestamp"
            fi
            if printf '%s\n' "$SYSLOG_WINDOW" | grep -qiE '/etc/shadow'; then
                add_detection "$NUMBER" "syslog" "identity" "Full" "user; file; timestamp"
            fi
            ;;

    esac

    AFTER=$(printf '%s' "$DETECTIONS" | jq 'length')
    FOUND=$((AFTER - BEFORE))

    if [ "$FOUND" -gt 0 ]; then
        CAPTURED=$((CAPTURED + 1))
    fi

    if [ "$FOUND" -gt 1 ]; then
        MULTI_SOURCE=$((MULTI_SOURCE + 1))
    fi

done < <(jq -c '.actions[]' "$GROUND_TRUTH_FILE")

jq -n \
    --argjson actions "$DETECTIONS" \
    --argjson total "$ACTIONS_COUNT" \
    --argjson captured "$CAPTURED" \
    --argjson multi "$MULTI_SOURCE" \
    '{
        simulation: "Linux Detection Proof",
        window_seconds: 30,
        actions: $actions,
        total_actions: $total,
        captured_actions: $captured,
        capture_percentage: (if $total > 0 then (($captured / $total) * 100) else 0 end),
        multi_source_actions: $multi
    }' > "$OUTPUT_FILE"

PERCENT=0
if [ "$ACTIONS_COUNT" -gt 0 ]; then
    PERCENT=$((CAPTURED * 100 / ACTIONS_COUNT))
fi

echo "Actions: $ACTIONS_COUNT | Captured: $CAPTURED/$ACTIONS_COUNT (${PERCENT}%) | Multi-source: $MULTI_SOURCE"
echo "Report saved to: $OUTPUT_FILE"
