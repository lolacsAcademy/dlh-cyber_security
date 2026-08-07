#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Inventory Linux log sources, formats, rotation policy, event rate and security relevance
# author: analyst

set -e
set -u
set -o pipefail

echo "[*] Discovering log sources..."

FOUND=0
MISSING=0

echo "Source | Path | Format | Rotation | Events/hr | Relevance"
echo "------ | ---- | ------ | -------- | --------- | ----------"

check_log() {
    NAME="$1"
    PATH_LOG="$2"
    FORMAT="$3"
    RELEVANCE="$4"

    if [ -f "$PATH_LOG" ]; then
        SIZE=$(du -h "$PATH_LOG" | awk '{print $1}')

        ROTATION=$(grep -R "$PATH_LOG" /etc/logrotate.d /etc/logrotate.conf 2>/dev/null | head -1 || true)
        if [ -z "$ROTATION" ]; then
            ROTATION="unknown"
        else
            ROTATION="configured"
        fi

        EVENTS=$(journalctl --since "1 hour ago" 2>/dev/null | wc -l || echo "<1")

        echo "$NAME | $PATH_LOG | $FORMAT | $ROTATION | $EVENTS | $RELEVANCE"
        FOUND=$((FOUND+1))
    else
        echo "$NAME | $PATH_LOG | MISSING"
        MISSING=$((MISSING+1))
    fi
}

check_log "auth.log" "/var/log/auth.log" "syslog" "critical"

check_log "audit.log" "/var/log/audit/audit.log" "audit" "critical"

check_log "syslog" "/var/log/syslog" "syslog" "high"

check_log "kern.log" "/var/log/kern.log" "syslog" "medium"

check_log "apache2 access" "/var/log/apache2/access.log" "combined" "high"

check_log "apache2 error" "/var/log/apache2/error.log" "custom" "high"

check_log "dpkg.log" "/var/log/dpkg.log" "custom" "medium"

echo ""
echo "[*] Checking missing security log sources..."

EXPECTED=(
"/var/log/auth.log"
"/var/log/audit/audit.log"
"/var/log/syslog"
)

for SRC in "${EXPECTED[@]}"; do
    if [ ! -f "$SRC" ]; then
        echo "Missing: $SRC"
    fi
done

echo ""
echo "Sources found: $FOUND | Missing: $MISSING"
