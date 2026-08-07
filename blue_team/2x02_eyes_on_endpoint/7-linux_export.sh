#!/bin/bash
# name: 7-linux_export.sh
# purpose: Export security-relevant Linux logs to structured JSON
# author: analyst
set -e
set -u
set -o pipefail
OUTPUT="linux_events_export.json"
TMP="/tmp/linux_events_export.jsonl"
HOSTNAME=$(hostname)
rm -f "$TMP"
echo "[*] Parsing auth.log..."
SSH_COUNT=0
SUDO_COUNT=0
SU_COUNT=0
PAM_COUNT=0
if [ -r /var/log/auth.log ]; then
    awk -v host="$HOSTNAME" '
    function esc(s) { gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/,"",s); return s }
    /sshd/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"auth.log\",\"eventcategory\":\"ssh\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    /sudo/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"auth.log\",\"eventcategory\":\"sudo\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    / su:/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"auth.log\",\"eventcategory\":\"su\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    /pam_/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"auth.log\",\"eventcategory\":\"PAM\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    ' /var/log/auth.log >> "$TMP"
    SSH_COUNT=$(grep -c '"eventcategory":"ssh"' "$TMP" 2>/dev/null || true)
    SUDO_COUNT=$(grep -c '"eventcategory":"sudo"' "$TMP" 2>/dev/null || true)
    SU_COUNT=$(grep -c '"eventcategory":"su"' "$TMP" 2>/dev/null || true)
    PAM_COUNT=$(grep -c '"eventcategory":"PAM"' "$TMP" 2>/dev/null || true)
fi
echo "    SSH logins: $SSH_COUNT | sudo: $SUDO_COUNT | su: $SU_COUNT | PAM: $PAM_COUNT"
echo "[*] Parsing audit.log..."
EXEC_COUNT=0
FILE_COUNT=0
NET_COUNT=0
if [ -r /var/log/audit/audit.log ]; then
    awk -v host="$HOSTNAME" '
    function esc(s) { gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/,"",s); return s }
    /execve/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"audit.log\",\"eventcategory\":\"execve\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    /type=PATH/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"audit.log\",\"eventcategory\":\"file_access\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    /socket|connect/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"audit.log\",\"eventcategory\":\"network\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    ' /var/log/audit/audit.log >> "$TMP"
    EXEC_COUNT=$(grep -c '"eventcategory":"execve"' "$TMP" 2>/dev/null || true)
    FILE_COUNT=$(grep -c '"eventcategory":"file_access"' "$TMP" 2>/dev/null || true)
    NET_COUNT=$(grep -c '"eventcategory":"network"' "$TMP" 2>/dev/null || true)
fi
echo "    execve: $EXEC_COUNT | file_access: $FILE_COUNT | network: $NET_COUNT"
echo "[*] Parsing syslog..."
SERVICE_COUNT=0
ERROR_COUNT=0
if [ -r /var/log/syslog ]; then
    awk -v host="$HOSTNAME" '
    function esc(s) { gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/,"",s); return s }
    /started|stopped|Starting|Stopping|service/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"syslog\",\"eventcategory\":\"service\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    /error|ERROR|failed|FAILED|failure/ { printf "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"sourcetype\":\"syslog\",\"eventcategory\":\"error\",\"message\":\"%s\"}\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime(), 1), host, esc($0) }
    ' /var/log/syslog >> "$TMP"
    SERVICE_COUNT=$(grep -c '"eventcategory":"service"' "$TMP" 2>/dev/null || true)
    ERROR_COUNT=$(grep -c '"eventcategory":"error"' "$TMP" 2>/dev/null || true)
fi
echo "    service: $SERVICE_COUNT | error: $ERROR_COUNT"
echo "[*] Creating linux_events_export.json..."
if [ -s "$TMP" ]; then
    jq -s '.' "$TMP" > "$OUTPUT"
else
    echo "[]" > "$OUTPUT"
fi
TOTAL=$(jq 'length' "$OUTPUT")
rm -f "$TMP"
echo ""
echo "Total events: $TOTAL"
echo "Output: $OUTPUT"
echo "[+] Linux telemetry export completed"
