#!/bin/bash
set -euo pipefail

# Task 6 - The Permission Sweep
# Addresses Crimson Tide Phase 3 (post-access privilege escalation):
# SUID/SGID binaries and world-writable files are classic escalation vectors.

# Known-safe SUID/SGID binaries on Kali/Ubuntu 22.04, including legitimate pentest tools
WHITELIST=(
  "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/gpasswd"
  "/usr/bin/chsh" "/usr/bin/chfn" "/usr/bin/newgrp" "/usr/bin/mount"
  "/usr/bin/umount" "/usr/bin/pkexec" "/usr/bin/fusermount3" "/usr/bin/at"
  "/usr/bin/crontab" "/usr/bin/chage" "/usr/bin/expiry"
  "/usr/lib/openssh/ssh-keysign" "/usr/lib/polkit-1/polkit-agent-helper-1"
  "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent"
  "/usr/lib/x86_64-linux-gnu/utempter/utempter"
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
  "/usr/sbin/pppd" "/usr/sbin/mount.nfs" "/usr/sbin/mount.cifs"
  "/usr/bin/ntfs-3g" "/usr/lib/xorg/Xorg.wrap" "/usr/lib/chromium/chrome-sandbox"
  "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool"
  "/usr/sbin/unix_chkpwd" "/usr/bin/dotlockfile" "/usr/bin/plocate"
  "/usr/bin/kismet_cap_ti_cc_2540" "/usr/bin/kismet_cap_rz_killerbee"
  "/usr/bin/kismet_cap_nrf_mousejack" "/usr/bin/kismet_cap_nrf_51822"
  "/usr/bin/kismet_cap_ubertooth_one" "/usr/bin/kismet_cap_linux_bluetooth"
  "/usr/bin/kismet_cap_ti_cc_2531" "/usr/bin/kismet_cap_linux_wifi"
  "/usr/bin/kismet_cap_hak5_wifi_coconut" "/usr/bin/kismet_cap_nxp_kw41z"
  "/usr/bin/kismet_cap_nrf_52840"
)

is_whitelisted() {
  local target="$1"
  for w in "${WHITELIST[@]}"; do
    [[ "$target" == "$w" ]] && return 0
  done
  return 1
}

# --- SUID ---
mapfile -t SUID_BINS < <(find / -xdev -perm -4000 -type f 2>/dev/null)
SUID_TOTAL=${#SUID_BINS[@]}
SUID_REMEDIATED=0
SUID_WHITELISTED=0
echo "Found $SUID_TOTAL SUID binaries"
for bin in "${SUID_BINS[@]}"; do
  if is_whitelisted "$bin"; then
    SUID_WHITELISTED=$((SUID_WHITELISTED + 1))
  else
    chmod u-s "$bin"
    printf '  %-25s [SUID REMOVED]\n' "$bin"
    SUID_REMEDIATED=$((SUID_REMEDIATED + 1))
  fi
done
echo "Whitelisted: $SUID_WHITELISTED"
echo "Non-whitelisted: $SUID_REMEDIATED"

# --- SGID ---
mapfile -t SGID_BINS < <(find / -xdev -perm -2000 -type f 2>/dev/null)
SGID_TOTAL=${#SGID_BINS[@]}
SGID_REMEDIATED=0
SGID_WHITELISTED=0
echo "Found $SGID_TOTAL SGID binaries"
for bin in "${SGID_BINS[@]}"; do
  if is_whitelisted "$bin"; then
    SGID_WHITELISTED=$((SGID_WHITELISTED + 1))
  else
    chmod g-s "$bin"
    printf '  %-25s [SGID REMOVED]\n' "$bin"
    SGID_REMEDIATED=$((SGID_REMEDIATED + 1))
  fi
done
echo "Whitelisted: $SGID_WHITELISTED"
echo "Non-whitelisted: $SGID_REMEDIATED"

# --- World-writable files ---
mapfile -t WW_FILES < <(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -perm -0002 -print 2>/dev/null)
WW_TOTAL=${#WW_FILES[@]}
echo "Found $WW_TOTAL world-writable files"
for f in "${WW_FILES[@]}"; do
  chmod o-w "$f"
  printf '  %-25s [FIXED]\n' "$f"
done

# --- Mount hardening: only touch dedicated mount points, never root fs ---
for mnt in /tmp /var/tmp /dev/shm; do
  if findmnt -T "$mnt" -no TARGET 2>/dev/null | grep -qx "$mnt"; then
    OPTS=$(findmnt -T "$mnt" -no OPTIONS)
    if [[ "$OPTS" == *noexec* && "$OPTS" == *nosuid* && "$OPTS" == *nodev* ]]; then
      printf '%-9s noexec,nosuid,nodev  [OK]\n' "${mnt}:"
    else
      mount -o remount,noexec,nosuid,nodev "$mnt"
      printf '%-9s noexec,nosuid,nodev  [APPLIED]\n' "${mnt}:"
    fi
  else
    printf '%-9s not a dedicated mount  [SKIPPED]\n' "${mnt}:"
  fi
done

# --- Cron restriction ---
echo "root" > /etc/cron.allow
whoami >> /etc/cron.allow
sort -u -o /etc/cron.allow /etc/cron.allow
chmod 600 /etc/cron.allow
rm -f /etc/cron.deny

echo "SUID remediated: $SUID_REMEDIATED | SGID remediated: $SGID_REMEDIATED | World-writable fixed: $WW_TOTAL"
