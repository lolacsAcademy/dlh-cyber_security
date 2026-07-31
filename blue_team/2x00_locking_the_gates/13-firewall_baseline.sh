#!/bin/bash
set -euo pipefail
# Task 13 - The Firewall Baseline
# Default-deny inbound, matching the reduced service set from Task 7.

echo "[*] Configuring UFW..."
ufw --force reset > /dev/null 2>&1 || true
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
echo "    Default incoming: deny"
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."
ufw allow from 10.10.1.0/24 to any port 22 proto tcp > /dev/null 2>&1
echo "    22/tcp from 10.10.1.0/24   [ADDED] SSH - management only"
ufw allow 80/tcp > /dev/null 2>&1
echo "    80/tcp                     [ADDED] HTTP"
ufw allow 443/tcp > /dev/null 2>&1
echo "    443/tcp                    [ADDED] HTTPS"
ufw allow from 10.10.2.0/24 to any port 3306 proto tcp > /dev/null 2>&1
echo "    3306/tcp from 10.10.2.0/24 [ADDED] MySQL - app network only"

echo "[*] Enabling logging..."
ufw logging low > /dev/null 2>&1
echo "    Logging: on (low)"

echo "[*] Activating firewall..."
ufw --force enable > /dev/null 2>&1 || true
STATUS=$(ufw status 2>/dev/null | head -1 | awk '{print $2}') || STATUS="unavailable"
RULE_COUNT=$(ufw status numbered 2>/dev/null | grep -c "ALLOW" || true)
echo "    UFW: $STATUS"
echo "    Rules: $RULE_COUNT allow, default deny"
