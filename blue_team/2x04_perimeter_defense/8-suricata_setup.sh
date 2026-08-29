#!/bin/bash
# fileinfo
# suricata.service
# do not start
set -euo pipefail

RULES_SRC="/home/analyst/MedDefense_Lab/suricata/rules"
RULES_DST="/var/lib/suricata/rules"
CONF="suricata.yaml"
OUT="setup_verification.json"
SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"
SMOKE_LOG="/tmp/suricata-smoke"

sudo apt-get update -qq
sudo apt-get install -y -qq suricata jq >/dev/null

sudo mkdir -p "$RULES_DST"
sudo cp -u "$RULES_SRC"/*.rules "$RULES_DST"/ 2>/dev/null || true
sudo cp -u "$RULES_SRC"/classification.config "$RULES_DST"/ 2>/dev/null || true

RULE_FILES_LOADED=$(ls "$RULES_DST"/*.rules 2>/dev/null | wc -l)

RULE_LIST=""
for f in "$RULES_DST"/*.rules; do
  RULE_LIST="${RULE_LIST}  - $(basename "$f")\n"
done
RULE_LIST="${RULE_LIST}  - meddefense.rules\n"

cat > "$CONF" << YAMLEOF
%YAML 1.1
---
default-rule-path: $RULES_DST
rule-files:
$(echo -e "$RULE_LIST")
default-log-dir: /var/log/suricata

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files

pcap-file:
  enabled: yes

vars:
  address-groups:
    HOME_NET: "[10.10.0.0/16]"
    EXTERNAL_NET: "!\$HOME_NET"
YAMLEOF

sudo mkdir -p /var/log/suricata

# Placeholder for meddefense.rules (built in a later task); prevents SC_ERR_NO_RULES
sudo touch "$RULES_DST/meddefense.rules"

CONFIG_TEST_EXIT=0
sudo suricata -T -c ./"$CONF" -v || CONFIG_TEST_EXIT=$?

sudo mkdir -p "$SMOKE_LOG"
sudo suricata -c ./"$CONF" -r "$SMOKE_PCAP" -l "$SMOKE_LOG" >/dev/null 2>&1 || true

SMOKE_ALERTS=0
if [ -f "$SMOKE_LOG/eve.json" ]; then
  SMOKE_ALERTS=$(sudo jq -s '[.[] | select(.event_type=="alert")] | length' "$SMOKE_LOG/eve.json" 2>/dev/null || echo 0)
fi

INSTALLED_VERSION=$(suricata -V 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
RULE_COUNT=$(sudo grep -h -c '^alert\|^drop\|^pass\|^reject' "$RULES_DST"/*.rules 2>/dev/null | awk '{s+=$1} END {print s}')

jq -n \
  --arg installed_version "$INSTALLED_VERSION" \
  --argjson rule_files_loaded "$RULE_FILES_LOADED" \
  --argjson rule_count "${RULE_COUNT:-0}" \
  --argjson config_test_exit "$CONFIG_TEST_EXIT" \
  --arg smoke_pcap "$SMOKE_PCAP" \
  --argjson smoke_alerts "$SMOKE_ALERTS" \
  '{
    installed_version: $installed_version,
    rule_files_loaded: $rule_files_loaded,
    rule_count: $rule_count,
    config_test_exit: $config_test_exit,
    smoke_pcap: $smoke_pcap,
    smoke_alerts: $smoke_alerts
  }' > "$OUT"

echo "Setup verification written to $OUT"
