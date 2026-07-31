#!/bin/bash
set -euo pipefail
# Task 15 - The Post-Hardening Validator (read-only, no changes made)
FAIL_COUNT=0

check() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "[PASS] $label = $actual"
  else
    echo "[FAIL] $label = $actual (expected: $expected)"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

SSHD="/etc/ssh/sshd_config"
get_ssh() { grep -iE "^$1[[:space:]]" "$SSHD" 2>/dev/null | awk '{print $2}' | tail -1; }
check "PermitRootLogin" "$(get_ssh PermitRootLogin)" "no"
check "PasswordAuthentication" "$(get_ssh PasswordAuthentication)" "no"
check "MaxAuthTries" "$(get_ssh MaxAuthTries)" "3"

get_sysctl() { sysctl -n "$1" 2>/dev/null; }
check "net.ipv4.ip_forward" "$(get_sysctl net.ipv4.ip_forward)" "0"
check "net.ipv4.tcp_syncookies" "$(get_sysctl net.ipv4.tcp_syncookies)" "1"
check "kernel.randomize_va_space" "$(get_sysctl kernel.randomize_va_space)" "2"
check "net.ipv4.conf.all.log_martians" "$(get_sysctl net.ipv4.conf.all.log_martians)" "1"

get_svc() { (systemctl is-active "$1" 2>/dev/null || service "$1" status 2>/dev/null | grep -qi running && echo active) || echo inactive; }
check "auditd.service" "$(get_svc auditd)" "active"
check "apparmor.service" "$(get_svc apparmor)" "active"

UFW_STATUS=$(ufw status 2>/dev/null | head -1 | awk '{print $2}'); UFW_STATUS="${UFW_STATUS:-inactive}"
check "UFW status" "$UFW_STATUS" "active"
UFW_DEFAULT=$(ufw status verbose 2>/dev/null | grep "Default:" | awk '{print $2}'); UFW_DEFAULT="${UFW_DEFAULT:-unknown}"
check "Default incoming" "$UFW_DEFAULT" "deny"

exit $([[ $FAIL_COUNT -eq 0 ]] && echo 0 || echo 1)
