#!/bin/bash
set -uo pipefail

OUT="unattended_config.json"
CONF_50="/etc/apt/apt.conf.d/50unattended-upgrades"
CONF_20="/etc/apt/apt.conf.d/20auto-upgrades"

# 1. Install unattended-upgrades if not present
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    echo "[*] unattended-upgrades: already installed"
    INSTALLED="already_installed"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
    INSTALLED="newly_installed"
fi

# 2. Write 50unattended-upgrades (idempotent: always overwrite with known-good content)
echo -n "[*] Writing $CONF_50...   "
cat > "$CONF_50" <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::Package-Blacklist {
    "linux-image*";
    "linux-headers*";
    "mysql-server*";
    "apache2*";
    "libapache2-mod-php*";
};

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "false";
EOF
echo "OK"

# 3. Write 20auto-upgrades (idempotent)
echo -n "[*] Writing $CONF_20...         "
cat > "$CONF_20" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "OK"

# 4. Enable and start timers
echo -n "[*] Enabling timers...                                     "
systemctl enable --now apt-daily.timer >/dev/null 2>&1
systemctl enable --now apt-daily-upgrade.timer >/dev/null 2>&1
TIMER_STATE=$(systemctl is-active apt-daily.timer apt-daily-upgrade.timer 2>/dev/null | tr '\n' ',' | sed 's/,$//')
echo "OK"

# 5. Dry run and parse output
echo "[*] Dry run..."
DRYRUN_FILE="/tmp/uu_dryrun_output.txt"
unattended-upgrades --dry-run --debug > "$DRYRUN_FILE" 2>&1

WOULD_UPGRADE_LINE=$(grep "^Packages that will be upgraded:" "$DRYRUN_FILE" | sed 's/^Packages that will be upgraded: //')
WOULD_UPGRADE_COUNT=0
if [ -n "$WOULD_UPGRADE_LINE" ]; then
    WOULD_UPGRADE_COUNT=$(echo "$WOULD_UPGRADE_LINE" | wc -w)
fi

SKIPPED_BLACKLIST_NAMES=$(grep "^skipping blacklisted package" "$DRYRUN_FILE" | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')
SKIPPED_BLACKLIST_COUNT=0
if [ -n "$SKIPPED_BLACKLIST_NAMES" ]; then
    SKIPPED_BLACKLIST_COUNT=$(echo "$SKIPPED_BLACKLIST_NAMES" | tr ',' '\n' | grep -c .)
fi

SKIPPED_HELD=$(grep -c "is not upgradable, as it's held back" "$DRYRUN_FILE" 2>/dev/null)
[ -z "$SKIPPED_HELD" ] && SKIPPED_HELD=0

echo "would upgrade:       $WOULD_UPGRADE_COUNT"
echo "skipped (blacklist): $SKIPPED_BLACKLIST_COUNT ($SKIPPED_BLACKLIST_NAMES)"
echo "skipped (held):      $SKIPPED_HELD"

BLACKLIST_JSON=$(jq -n '["linux-image*","linux-headers*","mysql-server*","apache2*","libapache2-mod-php*"]')
CONFIG_PATHS_JSON=$(jq -n --arg a "$CONF_50" --arg b "$CONF_20" '[$a,$b]')

DRY_RUN_SUMMARY=$(jq -n --argjson wu "$WOULD_UPGRADE_COUNT" --argjson sb "$SKIPPED_BLACKLIST_COUNT" --argjson sh "$SKIPPED_HELD" \
    '{would_upgrade:$wu, skipped_blacklisted:$sb, skipped_held:$sh}')

jq -n --arg installed "$INSTALLED" --argjson config_paths "$CONFIG_PATHS_JSON" \
    --argjson blacklist "$BLACKLIST_JSON" --arg timer_state "$TIMER_STATE" \
    --argjson dry_run_summary "$DRY_RUN_SUMMARY" \
    '{installed:$installed, config_paths:$config_paths, blacklist:$blacklist, timer_state:$timer_state, dry_run_summary:$dry_run_summary}' > "$OUT"

echo "Report saved to: $OUT"
