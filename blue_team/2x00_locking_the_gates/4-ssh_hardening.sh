#!/bin/bash
set -uo pipefail

# Task 4 - The SSH Lockdown
# Addresses 1x02 Finding 009 (SSH password auth + no lockout) and
# Crimson Tide Phase 3 (SSH used for lateral movement in 3/5 breaches).

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak"
BANNER="/etc/issue.net"

echo "[*] Backing up $SSHD_CONFIG"
cp -p "$SSHD_CONFIG" "$BACKUP"

# Idempotent: replace existing directive (commented or not) or append if absent.
set_directive() {
  local key="$1"
  local value="$2"
  local comment="$3"
  if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*|# ${comment}\n${key} ${value}|" "$SSHD_CONFIG"
  else
    printf '\n# %s\n%s %s\n' "$comment" "$key" "$value" >> "$SSHD_CONFIG"
  fi
}

echo "[*] Applying SSH hardening settings..."

set_directive "PermitRootLogin" "no" "Crimson Tide Phase 3 - removes root as an SSH lateral movement target"
echo "    PermitRootLogin no"

set_directive "PasswordAuthentication" "no" "1x02 Finding 009 - eliminates brute-force via password guessing"
echo "    PasswordAuthentication no"

set_directive "PermitEmptyPasswords" "no" "1x02 Finding 009 - closes trivial no-credential access"
echo "    PermitEmptyPasswords no"

set_directive "X11Forwarding" "no" "Reduces attack surface - X11 forwarding not required for MedDefense operations"
echo "    X11Forwarding no"

set_directive "MaxAuthTries" "3" "1x02 Finding 009 - throttles brute-force attempts per connection"
echo "    MaxAuthTries 3"

set_directive "ClientAliveInterval" "300" "Crimson Tide Phase 3 - limits window for session hijack on idle connections"
echo "    ClientAliveInterval 300"

set_directive "ClientAliveCountMax" "2" "Crimson Tide Phase 3 - enforces 10 min idle timeout (300s x 2)"
echo "    ClientAliveCountMax 2"

set_directive "AllowUsers" "medadmin sysadmin" "Crimson Tide Phase 3 - restricts SSH to named operational accounts only"
echo "    AllowUsers medadmin sysadmin"

set_directive "Protocol" "2" "Disables legacy SSHv1, vulnerable to known cryptographic attacks"
echo "    Protocol 2"

set_directive "LoginGraceTime" "60" "Reduces window for slow/incomplete auth-based DoS attempts"
echo "    LoginGraceTime 60"

set_directive "Banner" "$BANNER" "Legal warning banner for unauthorized access deterrence"
echo "    Banner /etc/issue.net"

echo "[*] Creating $BANNER"
cat > "$BANNER" << 'EOF'
***************************************************************************
                       AUTHORIZED ACCESS ONLY
This system is the property of MedDefense Health Systems. Unauthorized
access is prohibited and will be prosecuted to the fullest extent of
the law. All activity is monitored and logged.
***************************************************************************
EOF

echo "[*] Validating SSH configuration..."
if sshd -t 2>/tmp/sshd_test_err; then
  echo "    sshd -t: OK"
  echo "[*] Restarting SSH service..."
  systemctl restart ssh
  STATUS=$(systemctl is-active ssh)
  echo "    ssh.service: $STATUS (running)"
else
  echo "    sshd -t: FAILED"
  cat /tmp/sshd_test_err
  echo "[*] Restoring backup..."
  cp -p "$BACKUP" "$SSHD_CONFIG"
  exit 1
fi

echo "Settings applied: 11"
