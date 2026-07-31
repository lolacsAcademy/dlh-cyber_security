#!/bin/bash
set -euo pipefail
# Task 14 - Production Hardening Orchestrator
STEPS=(0-baseline_snapshot.sh 2-lynis_parse.sh 4-ssh_hardening.sh 5-sysctl_hardening.sh 6-filesystem_hardening.sh 7-service_minimization.sh 8-pam_hardening.sh 9-apparmor_config.sh 10-auditd_config.sh 11-audit_coverage_test.sh 12-log_config.sh 13-firewall_baseline.sh 15-validation.sh)
RUN_LOG="hardening_run.json"; IMP_LOG="hardening_improvement.json"
RESULTS=(); COMPLETED=0; FAILED=0

MISSING=()
for s in "${STEPS[@]}"; do [[ -f "$s" ]] || MISSING+=("$s"); done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Pre-checks: FAIL"; echo "Missing: ${MISSING[*]}"
  echo "{\"pre_checks\":\"FAIL\",\"missing\":\"${MISSING[*]}\"}" > "$RUN_LOG"
  echo "{\"before_lynis_score\":0,\"after_lynis_score\":0,\"delta\":0}" > "$IMP_LOG"
  exit 1
fi
echo "Pre-checks: PASS"

BEFORE=$(command -v lynis >/dev/null && lynis audit system --quick 2>&1 | grep -i "hardening index" | grep -oE "[0-9]+" | head -1) || true
BEFORE="${BEFORE:-0}"

for s in "${STEPS[@]}"; do
  START=$(date +%s)
  if [[ "$s" == "2-lynis_parse.sh" ]]; then
    lynis audit system --quick >/tmp/lynis_step.log 2>&1 || true
    if bash "./$s" /var/log/lynis-report.dat >"/tmp/${s}.out" 2>&1; then EC=0; ST=OK; COMPLETED=$((COMPLETED+1)); else EC=$?; ST=FAILED; FAILED=$((FAILED+1)); fi
  else
    if bash "./$s" >"/tmp/${s}.out" 2>&1; then EC=0; ST=OK; COMPLETED=$((COMPLETED+1)); else EC=$?; ST=FAILED; FAILED=$((FAILED+1)); fi
  fi
  DUR=$(($(date +%s)-START))
  RESULTS+=("{\"step\":\"$s\",\"status\":\"$ST\",\"exit_code\":$EC,\"duration_seconds\":$DUR}")
  if [[ "$ST" == "FAILED" ]]; then
    echo "Steps completed: $COMPLETED"; echo "Steps failed: $FAILED"; echo "Stopped at: $s"
    break
  fi
done

AFTER=$(command -v lynis >/dev/null && lynis audit system --quick 2>&1 | grep -i "hardening index" | grep -oE "[0-9]+" | head -1) || true
AFTER="${AFTER:-$BEFORE}"
DELTA=$((AFTER-BEFORE))

{ echo "{\"steps_scheduled\":${#STEPS[@]},\"steps_completed\":$COMPLETED,\"steps_failed\":$FAILED,\"steps\":["
  for i in "${!RESULTS[@]}"; do sep=","; [[ $i -eq $((${#RESULTS[@]}-1)) ]] && sep=""; echo "${RESULTS[$i]}$sep"; done
  echo "]}"; } > "$RUN_LOG"
echo "{\"before_lynis_score\":$BEFORE,\"after_lynis_score\":$AFTER,\"delta\":$DELTA}" > "$IMP_LOG"

if [[ "$FAILED" -eq 0 ]]; then
  echo "Steps scheduled: ${#STEPS[@]}"; echo "Steps completed: $COMPLETED"; echo "Steps failed: $FAILED"
  echo "Before Lynis score: $BEFORE"; echo "After Lynis score: $AFTER"; echo "Delta: +$DELTA"
fi
echo "Run log saved to: $RUN_LOG"
echo "Improvement saved to: $IMP_LOG"
