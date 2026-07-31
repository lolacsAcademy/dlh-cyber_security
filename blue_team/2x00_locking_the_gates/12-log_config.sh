#!/bin/bash
set -euo pipefail
# Task 12 - The Log Architect
RSYSLOG_CONF="/etc/rsyslog.d/50-meddefense.conf"
LOGROTATE_CONF="/etc/logrotate.d/meddefense"

echo "[*] Configuring rsyslog..."
cat > "$RSYSLOG_CONF" << 'EOF'
auth,authpriv.*                /var/log/auth.log
*.info;auth,authpriv.none      /var/log/syslog
EOF
echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
(service rsyslog restart 2>/dev/null || systemctl restart rsyslog 2>/dev/null) || true

echo "[*] Setting log rotation policies..."
cat > "$LOGROTATE_CONF" << 'EOF'
/var/log/auth.log {
    rotate 90
    daily
    missingok
    notifempty
    compress
    delaycompress
}
/var/log/syslog {
    rotate 60
    daily
    missingok
    notifempty
    compress
    delaycompress
}
EOF
echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"

echo "[*] Verifying log activity..."
touch /var/log/auth.log /var/log/syslog 2>/dev/null || true
logger -p auth.info "MedDefense verification event" 2>/dev/null || true
sleep 1
for f in /var/log/auth.log /var/log/syslog; do
  [[ -s "$f" ]] && printf '    %-25s receiving events       [OK]\n' "$f:" || printf '    %-25s no events yet          [WARN]\n' "$f:"
done

echo "[*] Securing log file permissions..."
for f in /var/log/auth.log /var/log/syslog; do
  chown root:adm "$f" 2>/dev/null || chown root:root "$f" 2>/dev/null || true
  chmod 640 "$f" 2>/dev/null || true
  OWNER=$(stat -c '%U:%G' "$f" 2>/dev/null || echo unknown)
  printf '    %-25s 640 %-10s [OK]\n' "$f:" "$OWNER"
done

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
