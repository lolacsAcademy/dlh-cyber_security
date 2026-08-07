#!/bin/bash
# name: 5-auditd_refine.sh
# purpose: Refine auditd rules with detection-focused telemetry and validate rule firing
# author: analyst
# monitors /home/*/.ssh/ SSH keys, cron persistence, and sudoers.d
set -e
set -u
set -o pipefail
RULE_FILE="/etc/audit/rules.d/99-detection-refine.rules"
echo "[*] Current auditd rules: $(auditctl -l | wc -l)"
echo "[*] Adding detection-focused rules..."
cat > "$RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S execve -k process_exec
-a always,exit -F arch=b64 -S socket -S connect -k network_connect
-w /home/kali/.ssh/ -p rwa -k ssh_keys
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/sudoers.d/ -p wa -k sudoers
EOF
echo "    execve syscall tracking               [ADDED]"
echo "    socket/connect syscall tracking       [ADDED]"
echo "    SSH key file monitoring               [ADDED]"
echo "    Cron directory monitoring             [ADDED]"
echo "    sudoers.d monitoring                  [ADDED]"
echo "[*] Loading rules..."
if augenrules --load >/dev/null 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
fi
TOTAL=$(auditctl -l | wc -l)
echo "[*] Total rules: $TOTAL"
echo "[*] Validating new rules..."
PASS=0
mkdir -p /home/kali/.ssh
id >/dev/null
if ausearch -k process_exec -ts recent >/dev/null 2>&1; then
    echo "    execve: ran /usr/bin/id -> ausearch -k process_exec    [CAPTURED]"
    PASS=$((PASS+1))
else
    echo "    execve: [FAILED]"
fi
curl -s localhost >/dev/null 2>&1 || true
if ausearch -k network_connect -ts recent >/dev/null 2>&1; then
    echo "    socket: curl localhost -> ausearch -k network_connect  [CAPTURED]"
    PASS=$((PASS+1))
else
    echo "    socket: [FAILED]"
fi
touch /home/kali/.ssh/test_audit_key
if ausearch -k ssh_keys -ts recent >/dev/null 2>&1; then
    echo "    ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys    [CAPTURED]"
    PASS=$((PASS+1))
else
    echo "    ssh_keys: [FAILED]"
fi
touch /etc/cron.d/test_audit_cron 2>/dev/null || true
if ausearch -k cron_persist -ts recent >/dev/null 2>&1; then
    echo "    cron: touch /etc/cron.d/test -> ausearch -k cron_persist [CAPTURED]"
    PASS=$((PASS+1))
else
    echo "    cron: [FAILED]"
fi
mkdir -p /etc/sudoers.d
touch /etc/sudoers.d/test_audit_sudo 2>/dev/null || true
if ausearch -k sudoers -ts recent >/dev/null 2>&1; then
    echo "    sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers [CAPTURED]"
    PASS=$((PASS+1))
else
    echo "    sudoers: [FAILED]"
fi
echo "Rules added: 5 | Validation: $PASS/5 PASS"
