#!/bin/bash

set -euo pipefail
# Task 0 - Baseline Snapshot
# Captures pre-hardening security state for delta comparison in later tasks.

OUTDIR="./baseline_output"
mkdir -p "$OUTDIR"

# 1. System identification
HOSTNAME=$(hostname)
OS=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
KERNEL=$(uname -r)
UPTIME=$(uptime -p)

# 2. Running services
(systemctl list-units --type=service --state=running --no-legend 2>/dev/null || echo "systemd unavailable") > "$OUTDIR/services_running.txt"
SERVICES_COUNT=$(wc -l < "$OUTDIR/services_running.txt")

# 3. Open ports / listening sockets (TCP + UDP)
sudo ss -tulnp > "$OUTDIR/open_ports.txt"
PORTS_COUNT=$(grep -E "LISTEN|UNCONN" "$OUTDIR/open_ports.txt" | wc -l || true)

# 4. SUID binaries
find / -xdev -perm -4000 -type f 2>/dev/null > "$OUTDIR/suid_binaries.txt"
SUID_COUNT=$(wc -l < "$OUTDIR/suid_binaries.txt")

# 5. SGID binaries
find / -xdev -perm -2000 -type f 2>/dev/null > "$OUTDIR/sgid_binaries.txt"
SGID_COUNT=$(wc -l < "$OUTDIR/sgid_binaries.txt")

# 6. World-writable files (excluding /proc, /sys, /dev)
sudo find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -perm -0002 -print 2>/dev/null > "$OUTDIR/world_writable.txt" || true
WW_COUNT=$(wc -l < "$OUTDIR/world_writable.txt")

# 7. Sysctl security-relevant parameters
sysctl -a 2>/dev/null | grep -E \
"net.ipv4.ip_forward|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.rp_filter|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.tcp_syncookies|kernel.randomize_va_space|fs.suid_dumpable|kernel.dmesg_restrict" \
> "$OUTDIR/sysctl_security.txt" || true

# 8. SSH configuration
sudo grep -E -i "^PermitRootLogin|^PasswordAuthentication|^PermitEmptyPasswords|^X11Forwarding|^Protocol|^MaxAuthTries" /etc/ssh/sshd_config > "$OUTDIR/ssh_config.txt" 2>/dev/null

# 9. Users and sudo group
awk -F: '$3 >= 1000 {print $1}' /etc/passwd > "$OUTDIR/user_accounts.txt"
getent group sudo > "$OUTDIR/sudo_group.txt"

# JSON structured output
cat > "$OUTDIR/baseline.json" <<EOF
{
  "hostname": "$HOSTNAME",
  "os": "$OS",
  "kernel": "$KERNEL",
  "uptime": "$UPTIME",
  "running_services": $SERVICES_COUNT,
  "open_ports": $PORTS_COUNT,
  "suid_binaries": $SUID_COUNT,
  "sgid_binaries": $SGID_COUNT,
  "world_writable_files": $WW_COUNT
}
EOF

# Console summary
echo "Hostname: $HOSTNAME"
echo "OS: $OS"
echo "Running services: $SERVICES_COUNT"
echo "Open ports: $PORTS_COUNT"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WW_COUNT"
