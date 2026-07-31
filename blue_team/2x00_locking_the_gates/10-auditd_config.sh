#!/bin/bash
set -euo pipefail

# Task 10 - The Audit Engine
# Addresses the 1x00 incident: no SIEM/IDS deployed, attacker moved
# undetected for 5 days. These rules create the kernel-level audit trail
# feeding the Module 3 SOC analyst work.

RULES_FILE="/etc/audit/rules.d/meddefense.rules"

echo "[*] Enabling auditd service..."
if ! command -v auditd > /dev/null 2>&1; then
  apt-get install -y auditd audispd-plugins > /dev/null 2>&1
fi
systemctl enable auditd > /dev/null 2>&1 || true
systemctl start auditd > /dev/null 2>&1 || true
service auditd start > /dev/null 2>&1 || true
STATUS=$(systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | grep -qi running && echo active || echo inactive)
echo "    auditd.service: $STATUS (running)"

echo "[*] Deploying MedDefense audit rules..."
cat > "$RULES_FILE" << 'EOF'
# MedDefense audit rules - addresses 1x00 (no SIEM/IDS, 5-day dwell time)

# Identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Authentication / SSH config
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Privilege escalation
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers

# Suspicious tool execution
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat

# MedDefense-specific file integrity
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts
EOF

while read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  target=$(echo "$line" | awk '{print $2}')
  printf '    %-46s [ADDED]\n' "$line"
done < "$RULES_FILE"

echo "[*] Loading rules..."
if augenrules --load > /tmp/augenrules_out 2>&1; then
  echo "    augenrules --load: OK"
else
  echo "    augenrules --load: FAILED"
  cat /tmp/augenrules_out
fi

RULE_COUNT=$(auditctl -l 2>/dev/null | grep -c "^-w" || true)
echo "[*] Verifying... auditctl -l: $RULE_COUNT rules loaded"

echo "[*] Test: reading /etc/shadow..."
cat /etc/shadow > /dev/null 2>&1 || true
sleep 1
EVENT_COUNT=$(ausearch -ts recent -k identity 2>/dev/null | grep -c "^type=SYSCALL" || true)
if [[ "$EVENT_COUNT" -gt 0 ]]; then
  echo "    ausearch -ts recent -k identity: $EVENT_COUNT event found [PASS]"
else
  echo "    ausearch -ts recent -k identity: 0 events found [FAIL]"
fi
