#!/bin/bash
set -euo pipefail
# Task 11 - Audit Telemetry Coverage Test
# Runs six controlled audit events and verifies capture
REPORT="audit_validation.json"
TFILE="/tmp/meddefense_audit_test.txt"
RESULTS=(); CAPTURED=0; TOTAL=6

cleanup() { rm -f "$TFILE"; auditctl -W "$TFILE" -k audit_test_file 2>/dev/null || true; auditctl -W /etc/crontab -k audit_test_cron 2>/dev/null || true; }
trap cleanup EXIT

chk() { sleep 1; ausearch -ts recent -k "$1" 2>/dev/null | grep -c "^type=SYSCALL" || true; }
rec() { RESULTS+=("{\"test\":\"$2\",\"audit_key\":\"$3\",\"command\":\"$4\",\"timestamp\":\"$(date -Iseconds)\",\"status\":\"$5\",\"event_count\":$6}"); printf '[%d/%d] %-38s [%s]\n' "$1" "$TOTAL" "$2" "$5"; }

echo "[*] Running audit telemetry coverage tests..."

sudo whoami >/dev/null 2>&1; c=$(chk priv_esc); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 1 "sudo execution" priv_esc "sudo whoami" "$s" "$c"
sudo cat /etc/shadow >/dev/null 2>&1; c=$(chk identity); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 2 "shadow access" identity "cat /etc/shadow" "$s" "$c"
wget --version >/dev/null 2>&1 || true; c=$(chk suspicious_download); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 3 "suspicious download tool" suspicious_download "wget --version" "$s" "$c"
cat /etc/ssh/sshd_config >/dev/null 2>&1; c=$(chk sshd_config); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 4 "sshd config read" sshd_config "cat sshd_config" "$s" "$c"
auditctl -w "$TFILE" -p wa -k audit_test_file 2>/dev/null || true; echo test > "$TFILE"; c=$(chk audit_test_file); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 5 "monitored test file write" audit_test_file "echo > $TFILE" "$s" "$c"
auditctl -w /etc/crontab -p r -k audit_test_cron 2>/dev/null || true; cat /etc/crontab >/dev/null 2>&1 || true; c=$(chk audit_test_cron); [[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED; rec 6 "cron configuration check" audit_test_cron "cat /etc/crontab" "$s" "$c"

echo "[*] Cleaning test artifacts..."
cleanup; trap - EXIT

{
  echo "{\"tests\":["
  for i in "${!RESULTS[@]}"; do sep=","; [[ $i -eq $((${#RESULTS[@]}-1)) ]] && sep=""; echo "  ${RESULTS[$i]}$sep"; done
  echo "],\"tests_executed\":$TOTAL,\"captured\":$CAPTURED,\"missed\":$((TOTAL-CAPTURED))}"
} > "$REPORT"

echo "Tests executed: $TOTAL"
echo "Captured: $CAPTURED"
echo "Missed: $((TOTAL-CAPTURED))"
echo "Report saved to: $REPORT"
