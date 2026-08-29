#!/bin/bash
set -euo pipefail

# Task 7 - The Service Minimizer
# Addresses CIS Section 2 + 1x02 Finding 006 (MySQL bound to 0.0.0.0).
# Reduces attack surface to only services MedDefense operations require.
#
# SAFETY: runs in DRY-RUN mode by default (reports only, changes nothing).
# Pass --apply as the first argument to actually stop/disable services.
# This protects a live/desktop machine from losing network or GUI services
# that would be irrelevant on the real billing-srv-01 target.

MODE="dry-run"
if [[ "${1:-}" == "--apply" ]]; then
  MODE="apply"
fi

# MedDefense required services (billing-srv-01 role)
WHITELIST=(
  "ssh.service"               # remote administration (hardened in Task 4)
  "apache2.service"           # patient billing web application
  "mysql.service"             # billing database backend
  "ufw.service"                # host firewall (Task 3 CIS-FW-01)
  "auditd.service"            # audit logging (Task 3 CIS-AUD-01)
  "apparmor.service"          # mandatory access control
  "cron.service"               # scheduled maintenance jobs
  "rsyslog.service"           # local log collection
  "systemd-timesyncd.service" # accurate timestamps for audit/log correlation
)

is_whitelisted() {
  local svc="$1"
  for w in "${WHITELIST[@]}"; do
    [[ "$svc" == "$w" ]] && return 0
  done
  return 1
}

echo "[*] Scanning enabled services..."
mapfile -t ENABLED < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}')
BEFORE=${#ENABLED[@]}
echo "    Enabled services found: $BEFORE"

echo "[*] Comparing against MedDefense whitelist (${#WHITELIST[@]} required services)... mode=$MODE"

DISABLED_COUNT=0
for svc in "${ENABLED[@]}"; do
  if is_whitelisted "$svc"; then
    STATE=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    printf '  %-25s [%s]\n' "$svc" "${STATE^^}"
  else
    if [[ "$MODE" == "apply" ]]; then
      systemctl stop "$svc" 2>/dev/null || true
      systemctl disable "$svc" 2>/dev/null || true
      printf '  %-25s [STOPPED] [DISABLED]\n' "$svc"
    else
      printf '  %-25s [WOULD STOP] [WOULD DISABLE]\n' "$svc"
    fi
    DISABLED_COUNT=$((DISABLED_COUNT + 1))
  fi
done

if [[ "$MODE" == "apply" ]]; then
  mapfile -t AFTER_LIST < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}')
  AFTER=${#AFTER_LIST[@]}
else
  AFTER=$((BEFORE - DISABLED_COUNT))
fi

echo "Before: $BEFORE | After: $AFTER | Disabled: $DISABLED_COUNT"
[[ "$MODE" == "dry-run" ]] && echo "[*] Dry-run only - no changes made. Re-run with --apply to enforce."
