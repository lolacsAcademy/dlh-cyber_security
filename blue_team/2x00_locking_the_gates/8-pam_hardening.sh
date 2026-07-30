#!/bin/bash
set -uo pipefail

# Task 8 - The PAM Fortress
# Addresses Crimson Tide Phase 2/3: harvested credentials + weak passwords
# used for lateral movement in 3/5 breaches.
# SAFETY: backs up every PAM file before editing. Does not touch
# /etc/pam.d/common-auth structure beyond the documented pam_faillock lines.

PWQUALITY_CONF="/etc/security/pwquality.conf"
COMMON_PASSWORD="/etc/pam.d/common-password"
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"

for f in "$PWQUALITY_CONF" "$COMMON_PASSWORD" "$COMMON_AUTH" "$COMMON_ACCOUNT"; do
  cp -p "$f" "${f}.bak.$(date +%s)" 2>/dev/null || true
done

echo "[*] Checking libpam-pwquality..."
if dpkg -l libpam-pwquality 2>/dev/null | grep -q "^ii"; then
  VER=$(dpkg -s libpam-pwquality | grep '^Version' | awk '{print $2}')
  echo "    Already installed: libpam-pwquality $VER"
else
  apt-get install -y libpam-pwquality > /dev/null 2>&1
  VER=$(dpkg -s libpam-pwquality | grep '^Version' | awk '{print $2}')
  echo "    Installed: libpam-pwquality $VER"
fi

echo "[*] Configuring password quality ($PWQUALITY_CONF)..."
set_pwquality() {
  local key="$1"
  local value="$2"
  if grep -qE "^[#[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$PWQUALITY_CONF"
  else
    echo "${key} = ${value}" >> "$PWQUALITY_CONF"
  fi
  printf '    %-30s [SET]\n' "${key} = ${value}"
}
set_pwquality "minlen" "14"
set_pwquality "dcredit" "-1"
set_pwquality "ucredit" "-1"
set_pwquality "lcredit" "-1"
set_pwquality "ocredit" "-1"
set_pwquality "maxrepeat" "3"
if grep -qE "^[#[:space:]]*reject_username" "$PWQUALITY_CONF"; then
  sed -i -E "s|^[#[:space:]]*reject_username.*|reject_username|" "$PWQUALITY_CONF"
else
  echo "reject_username" >> "$PWQUALITY_CONF"
fi
printf '    %-30s [SET]\n' "reject_username"

echo "[*] Configuring account lockout (pam_faillock)..."
# pam-auth-update handles the standard Debian/Ubuntu pam_faillock profile.
if ! grep -q "pam_faillock" "$COMMON_AUTH"; then
  sed -i '/pam_unix.so/i auth        required                        pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900' "$COMMON_AUTH"
  sed -i '/pam_unix.so/a auth        [default=die]                   pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900' "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock" "$COMMON_ACCOUNT"; then
  echo "account     required                        pam_faillock.so" >> "$COMMON_ACCOUNT"
fi
printf '    %-30s [SET]\n' "deny = 5"
printf '    %-30s [SET]\n' "unlock_time = 900"
printf '    %-30s [SET]\n' "fail_interval = 900"

echo "[*] Configuring password history..."
if grep -qE "pam_unix\.so.*remember=" "$COMMON_PASSWORD"; then
  sed -i -E "s/remember=[0-9]+/remember=12/" "$COMMON_PASSWORD"
elif grep -qE "^password.*pam_unix\.so" "$COMMON_PASSWORD"; then
  sed -i -E "s/(^password\s+\[?[a-zA-Z0-9=_ ]*\]?\s+pam_unix\.so.*)/\1 remember=12/" "$COMMON_PASSWORD"
fi
printf '    %-30s [SET]\n' "remember = 12"

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
