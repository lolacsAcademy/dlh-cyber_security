#!/bin/bash
set -uo pipefail

MODE="${1:-}"

RULE_SOURCE="${MEDDEFENSE_RULES_SOURCE:-./meddefense.rules}"
RULE_DEST="/etc/audit/rules.d/meddefense.rules"

TELEMETRY_DIR="capstone/telemetry"
EVENTS_OUT="capstone/telemetry/linux_events.json"
COVERAGE_OUT="capstone/telemetry/linux_coverage.json"

TEST_USER="mdtelemetrytest"
TEST_CRON="/etc/cron.d/meddefense-telemetry-test"

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment/input error

for cmd in jq systemctl auditctl ausearch find date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

echo "Linux telemetry deployment"

# ------------------------------------------------------------
# SAFE DEFAULT
# ------------------------------------------------------------
if [ "$MODE" != "--apply" ]; then
    echo "SAFE MODE: no telemetry or system changes will be applied."

    if [ -f "$RULE_SOURCE" ]; then
        echo "[OK] project audit rules: $RULE_SOURCE"
    else
        echo "[MISSING] project audit rules: $RULE_SOURCE"
    fi

    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo "[OK] auditd currently active"
    else
        echo "[INFO] auditd currently inactive"
    fi

    echo "Required destination: $RULE_DEST"
    echo "Real deployment requires: $0 --apply"

    exit 0
fi

# ------------------------------------------------------------
# APPLY MODE - modifies Linux
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --apply requires root" >&2
    exit 2
fi

if [ ! -f "$RULE_SOURCE" ]; then
    echo "ERROR: missing project rules file: $RULE_SOURCE" >&2
    exit 2
fi

mkdir -p "$TELEMETRY_DIR"

# Refuse to delete/replace objects that may belong to someone else.
if id "$TEST_USER" >/dev/null 2>&1; then
    echo "ERROR: test user already exists: $TEST_USER" >&2
    exit 1
fi

if [ -e "$TEST_CRON" ]; then
    echo "ERROR: test cron file already exists: $TEST_CRON" >&2
    exit 1
fi

# ------------------------------------------------------------
# Ensure project audit rules are installed idempotently.
# ------------------------------------------------------------
if [ ! -f "$RULE_DEST" ] ||
    ! cmp -s "$RULE_SOURCE" "$RULE_DEST"; then

    install -m 0640 "$RULE_SOURCE" "$RULE_DEST"
fi

if ! systemctl is-active --quiet auditd; then
    systemctl start auditd
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$RULE_DEST"
fi

if ! systemctl is-active --quiet auditd; then
    echo "ERROR: auditd is not active" >&2
    exit 1
fi

# ------------------------------------------------------------
# Controlled authorized test sequence
# ------------------------------------------------------------

# 1. Create user.
useradd "$TEST_USER"

# 2. Remove user.
userdel "$TEST_USER"

# 3. Service management action.
# Reload cron when possible to avoid stopping the service.
if systemctl reload cron >/dev/null 2>&1; then
    :
elif systemctl reload crond >/dev/null 2>&1; then
    :
else
    echo "ERROR: unable to perform controlled service action" >&2
    exit 1
fi

# 4. Schedule a cron job.
printf '%s\n' \
    '* * * * * root /bin/true' \
    > "$TEST_CRON"

chmod 0644 "$TEST_CRON"

# 5. Remove cron job.
rm -f "$TEST_CRON"

# 6. Short authorized find as root.
find /etc \
    -maxdepth 1 \
    -type f \
    -name passwd \
    -print >/dev/null

sleep 2

# ------------------------------------------------------------
# Coverage verification
# ------------------------------------------------------------
COVERAGE='[]'
ALL_DETECTED=true

check_key() {
    local action="$1"
    local key="$2"
    local output
    local detected=false
    local count=0
    local entry

    output=$(ausearch -k "$key" -ts recent 2>/dev/null || true)

    if printf '%s\n' "$output" | grep -q 'type='; then
        detected=true
        count=$(printf '%s\n' "$output" |
            grep -c 'type=' || true)
    else
        ALL_DETECTED=false
    fi

    entry=$(jq -n \
        --arg action "$action" \
        --arg key "$key" \
        --argjson detected "$detected" \
        --argjson evidence_count "$count" \
        '{
            action: $action,
            expected_source: "auditd",
            expected_key: $key,
            detected: $detected,
            evidence_count: $evidence_count
        }')

    COVERAGE=$(printf '%s\n' "$COVERAGE" |
        jq --argjson entry "$entry" '. + [$entry]')
}

check_key "create_user" "meddefense-user-mgmt"
check_key "remove_user" "meddefense-user-mgmt"
check_key "service_management" "meddefense-service-mgmt"
check_key "create_cron_job" "meddefense-cron"
check_key "remove_cron_job" "meddefense-cron"
check_key "authorized_find_root" "meddefense-root-find"

jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson actions "$COVERAGE" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        actions: $actions
    }' > "$COVERAGE_OUT"

# ------------------------------------------------------------
# Export last 30 minutes of auditd and syslog as structured JSON
# ------------------------------------------------------------
SINCE=$(date -d '30 minutes ago' '+%m/%d/%Y %H:%M:%S')

AUDIT_TEXT=$(ausearch \
    --start "$SINCE" \
    -i 2>/dev/null || true)

if command -v journalctl >/dev/null 2>&1; then
    SYSLOG_TEXT=$(journalctl \
        --since "30 minutes ago" \
        --no-pager 2>/dev/null || true)
elif [ -r /var/log/syslog ]; then
    SYSLOG_TEXT=$(tail -n 5000 /var/log/syslog)
else
    SYSLOG_TEXT=""
fi

jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg audit "$AUDIT_TEXT" \
    --arg syslog "$SYSLOG_TEXT" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        window_minutes: 30,
        auditd: (
            $audit
            | split("\n")
            | map(select(length > 0))
        ),
        syslog: (
            $syslog
            | split("\n")
            | map(select(length > 0))
        )
    }' > "$EVENTS_OUT"

if ! jq empty "$EVENTS_OUT" >/dev/null 2>&1 ||
    ! jq empty "$COVERAGE_OUT" >/dev/null 2>&1; then

    echo "ERROR: structured telemetry output invalid" >&2
    exit 1
fi

echo "Telemetry export: $EVENTS_OUT"
echo "Coverage evidence: $COVERAGE_OUT"

if [ "$ALL_DETECTED" != true ]; then
    echo "ERROR: one or more authorized actions were not detected" >&2
    exit 1
fi

exit 0
