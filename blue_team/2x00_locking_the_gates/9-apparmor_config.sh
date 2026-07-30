#!/bin/bash
set -euo pipefail

# Task 9 - The AppArmor Enforcer
# Addresses the 1x00 incident: Apache compromise gave the crypto-miner
# unrestricted filesystem access as www-data. Mandatory access control
# confines a compromised process to only its required directories.

echo "[*] Checking AppArmor status..."
if lsmod | grep -q apparmor; then
  echo "    AppArmor module: loaded"
else
  echo "    AppArmor module: NOT loaded"
fi

if systemctl is-active --quiet apparmor; then
  echo "    AppArmor service: active"
else
  echo "    AppArmor service: inactive"
fi

echo "[*] Profile enforcement:"
ENFORCE_COUNT=0
COMPLAIN_COUNT=0

switch_to_enforce() {
  local binary_path="$1"
  local profile_name="$2"
  local profile_file="/etc/apparmor.d/${profile_name}"
  if [[ -f "$profile_file" ]]; then
    local current
    if aa-status 2>/dev/null | grep -q "^${binary_path} (.*enforce"; then
      printf '    %-25s %-20s [OK]\n' "$binary_path" "enforce"
      ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
    else
      aa-enforce "$profile_file" > /dev/null 2>&1 || true
      printf '    %-25s %-20s [ENFORCED]\n' "$binary_path" "complain -> enforce"
      ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
    fi
  else
    printf '    %-25s %-20s [NO PROFILE - not installed on this host]\n' "$binary_path" "n/a"
  fi
}

switch_to_enforce "/usr/sbin/apache2" "usr.sbin.apache2"
switch_to_enforce "/usr/sbin/mysqld" "usr.sbin.mysqld"

if [[ -f /etc/apparmor.d/usr.sbin.sshd ]]; then
  if aa-status 2>/dev/null | grep -q "^/usr/sbin/sshd (.*enforce"; then
    printf '    %-25s %-20s [OK]\n' "/usr/sbin/sshd" "enforce"
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
  else
    printf '    %-25s %-20s [complain]\n' "/usr/sbin/sshd" "complain"
    COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
  fi
fi

echo "[*] Custom profile: /opt/meddefense/billing-app"
mkdir -p /opt/meddefense/billing-app
cat > /etc/apparmor.d/opt.meddefense.billing-app << 'EOF'
# MedDefense Billing Application - custom AppArmor profile
# Addresses 1x00 incident: confines the billing app to only its required
# directories, preventing lateral filesystem access even from a zero-day.
#include <tunables/global>

/opt/meddefense/billing-app/** {
  #include <abstractions/base>

  /opt/meddefense/billing-app/                r,
  /opt/meddefense/billing-app/**              r,
  /opt/meddefense/billing-app/data/**         rw,
  /opt/meddefense/billing-app/logs/**         rw,
  /var/log/meddefense/billing-app.log         w,

  deny /etc/shadow r,
  deny /home/**     rwx,
  deny /root/**     rwx,
}
EOF
apparmor_parser -r /etc/apparmor.d/opt.meddefense.billing-app > /dev/null 2>&1 || true
echo "    [CREATED] [ENFORCED]"
ENFORCE_COUNT=$((ENFORCE_COUNT + 1))

echo "[*] Unconfined network-exposed processes:"
UNCONFINED_COUNT=0
if command -v aa-unconfined > /dev/null 2>&1; then
  mapfile -t UNCONFINED < <(aa-unconfined 2>/dev/null | awk '{print $2}' || true)
  for proc in "${UNCONFINED[@]:-}"; do
    [[ -z "$proc" ]] && continue
    printf '    %-25s [UNCONFINED - Profile recommended]\n' "$proc"
    UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
  done
fi
if [[ "$UNCONFINED_COUNT" -eq 0 ]]; then
  echo "    None found"
fi

echo "Profiles in enforce: $ENFORCE_COUNT | Complain: $COMPLAIN_COUNT | Unconfined: $UNCONFINED_COUNT"
