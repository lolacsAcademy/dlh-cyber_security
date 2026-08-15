#!/bin/bash
# Hawthorne
# 5-firewall_test.sh
# suricata_alerts.json
set -uo pipefail

MODE="${1:-}"

ARTIFACT_DIR="capstone/network"
SUMMARY="$ARTIFACT_DIR/network_deploy_summary.json"

SEGMENTATION="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAP_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs"
DNS_BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"

NETWORK_PIPELINE="${NETWORK_PIPELINE_SCRIPT:-./4-nftables_config.sh}"
FIREWALL_VALIDATOR="${FIREWALL_VALIDATOR_SCRIPT:-./firewall_validation.sh}"
CUSTOM_RULE_VALIDATOR="${CUSTOM_RULE_VALIDATOR_SCRIPT:-./suricata_rule_validation.sh}"

SURICATA_RULES="${SURICATA_RULES_FILE:-./suricata_custom.rules}"
DNSMASQ_CONF="/etc/dnsmasq.d/meddefense-capstone.conf"

export CAPSTONE_ARTIFACTS_DIR="capstone/network/"
export SEGMENTATION_RULES="$SEGMENTATION"

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment/input error

for cmd in jq find; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

echo "Capstone network defense deployment"

# ------------------------------------------------------------
# Required inputs
# ------------------------------------------------------------
if [ ! -s "$SEGMENTATION" ]; then
    echo "ERROR: missing segmentation file: $SEGMENTATION" >&2
    exit 2
fi

if ! jq empty "$SEGMENTATION" >/dev/null 2>&1; then
    echo "ERROR: invalid segmentation_rules.json" >&2
    exit 2
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo "ERROR: missing PCAP directory: $PCAP_DIR" >&2
    exit 2
fi

PCAP_COUNT=$(
    find "$PCAP_DIR" \
        -maxdepth 1 \
        -type f \
        \( -name '*.pcap' -o -name '*.pcapng' \) |
        wc -l
)

if [ "$PCAP_COUNT" -eq 0 ]; then
    echo "ERROR: no PCAP files found in $PCAP_DIR" >&2
    exit 2
fi

if [ ! -s "$DNS_BLOCKLIST" ]; then
    echo "ERROR: missing DNS blocklist: $DNS_BLOCKLIST" >&2
    exit 2
fi

# ------------------------------------------------------------
# SAFE DEFAULT
# ------------------------------------------------------------
if [ "$MODE" != "--apply" ]; then
    echo
    echo "SAFE MODE: no firewall, Suricata service, DNS, or system changes will be applied."
    echo "[OK] CAPSTONE_ARTIFACTS_DIR=$CAPSTONE_ARTIFACTS_DIR"
    echo "[OK] Segmentation: $SEGMENTATION"
    echo "[OK] PCAP files: $PCAP_COUNT"
    echo "[OK] DNS blocklist: $DNS_BLOCKLIST"

    if [ -f "$NETWORK_PIPELINE" ]; then
        echo "[OK] Network pipeline: $NETWORK_PIPELINE"
    else
        echo "[MISSING] Network pipeline: $NETWORK_PIPELINE"
    fi

    if [ -f "$FIREWALL_VALIDATOR" ]; then
        echo "[OK] Firewall validator: $FIREWALL_VALIDATOR"
    else
        echo "[MISSING] Firewall validator: $FIREWALL_VALIDATOR"
    fi

    if command -v suricata >/dev/null 2>&1; then
        echo "[OK] Suricata present"
    else
        echo "[MISSING] Suricata"
    fi

    echo
    echo "Real network deployment requires:"
    echo "$0 --apply"

    exit 0
fi

# ------------------------------------------------------------
# APPLY MODE
# Everything below can modify network state.
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --apply requires root privileges" >&2
    exit 2
fi

for cmd in nft suricata dnsmasq systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

if [ ! -f "$NETWORK_PIPELINE" ]; then
    echo "ERROR: missing network pipeline: $NETWORK_PIPELINE" >&2
    exit 2
fi

if [ ! -f "$FIREWALL_VALIDATOR" ]; then
    echo "ERROR: missing firewall validator: $FIREWALL_VALIDATOR" >&2
    exit 2
fi

mkdir -p "$ARTIFACT_DIR"

# ------------------------------------------------------------
# Capture network state BEFORE change
# ------------------------------------------------------------
BEFORE_RULESET="$ARTIFACT_DIR/nftables_before.nft"

nft list ruleset > "$BEFORE_RULESET"

jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg segmentation "$SEGMENTATION" \
    --arg ruleset "$BEFORE_RULESET" \
    '{
        timestamp: $timestamp,
        segmentation_rules: $segmentation,
        before_ruleset: $ruleset
    }' > "$ARTIFACT_DIR/network_before.json"

# ------------------------------------------------------------
# Invoke prior network pipeline with capstone artifact directory
# ------------------------------------------------------------
set +e

CAPSTONE_ARTIFACTS_DIR="capstone/network/" \
SEGMENTATION_RULES="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json" \
"$NETWORK_PIPELINE" --apply \
    >"$ARTIFACT_DIR/network_pipeline.stdout" \
    2>"$ARTIFACT_DIR/network_pipeline.stderr"

PIPELINE_EXIT=$?

set -e

if [ "$PIPELINE_EXIT" -ne 0 ]; then
    echo "ERROR: network pipeline failed" >&2
    exit 1
fi

# ------------------------------------------------------------
# Firewall validation suite
# Refuse to proceed if any test fails.
# ------------------------------------------------------------
set +e

"$FIREWALL_VALIDATOR" \
    >"$ARTIFACT_DIR/firewall_validation.log" \
    2>&1

FIREWALL_EXIT=$?

set -e

if [ "$FIREWALL_EXIT" -ne 0 ]; then
    echo "ERROR: firewall validation failed" >&2
    exit 1
fi

# ------------------------------------------------------------
# Suricata offline replay ONLY
# Required: suricata -r <PCAP>
# ------------------------------------------------------------
SURICATA_DIR="$ARTIFACT_DIR/suricata"
mkdir -p "$SURICATA_DIR"

SURICATA_RESULTS='[]'
SURICATA_FAILED=0

while IFS= read -r pcap; do
    name=$(basename "$pcap")
    run_dir="$SURICATA_DIR/${name%.*}"

    mkdir -p "$run_dir"

    set +e

    suricata \
        -r "$pcap" \
        -l "$run_dir" \
        >"$run_dir/suricata.stdout" \
        2>"$run_dir/suricata.stderr"

    rc=$?

    set -e

    if [ "$rc" -ne 0 ]; then
        SURICATA_FAILED=1
    fi

    eve="$run_dir/eve.json"
    alerts="$run_dir/alerts.json"

    if [ -s "$eve" ]; then
        jq -s '
            [
                .[]
                | select(.event_type == "alert")
            ]
        ' "$eve" > "$alerts"
    else
        printf '[]\n' > "$alerts"
    fi

    alert_count=$(jq 'length' "$alerts")

    entry=$(
        jq -n \
            --arg pcap "$pcap" \
            --arg alerts "$alerts" \
            --argjson exit_code "$rc" \
            --argjson alert_count "$alert_count" \
            '{
                pcap: $pcap,
                exit_code: $exit_code,
                parsed_alerts: $alerts,
                alert_count: $alert_count
            }'
    )

    SURICATA_RESULTS=$(
        printf '%s\n' "$SURICATA_RESULTS" |
            jq --argjson entry "$entry" '. + [$entry]'
    )

done < <(
    find "$PCAP_DIR" \
        -maxdepth 1 \
        -type f \
        \( -name '*.pcap' -o -name '*.pcapng' \) |
        sort
)

if [ "$SURICATA_FAILED" -ne 0 ]; then
    echo "ERROR: one or more Suricata offline replay runs failed" >&2
    exit 1
fi

# ------------------------------------------------------------
# Custom rule validation against labeled PCAPs
# ------------------------------------------------------------
CUSTOM_RULE_EXIT=0

if [ -f "$CUSTOM_RULE_VALIDATOR" ]; then
    set +e

    "$CUSTOM_RULE_VALIDATOR" \
        >"$ARTIFACT_DIR/custom_rule_validation.log" \
        2>&1

    CUSTOM_RULE_EXIT=$?

    set -e

    if [ "$CUSTOM_RULE_EXIT" -ne 0 ]; then
        echo "ERROR: custom Suricata rule validation failed" >&2
        exit 1
    fi
fi

# ------------------------------------------------------------
# dnsmasq local DNS filter
# Configure idempotently from capstone blocklist
# ------------------------------------------------------------
DNS_TMP="$ARTIFACT_DIR/dnsmasq-capstone.conf"

{
    echo "# Managed by MedDefense capstone"

    while IFS= read -r domain; do
        domain=${domain%%#*}
        domain=$(printf '%s' "$domain" | xargs)

        [ -n "$domain" ] || continue

        printf 'address=/%s/0.0.0.0\n' "$domain"
    done < "$DNS_BLOCKLIST"

} > "$DNS_TMP"

if [ ! -f "$DNSMASQ_CONF" ] ||
    ! cmp -s "$DNS_TMP" "$DNSMASQ_CONF"; then
    cp "$DNS_TMP" "$DNSMASQ_CONF"
fi

if ! dnsmasq --test >/dev/null 2>&1; then
    echo "ERROR: dnsmasq configuration validation failed" >&2
    exit 1
fi

systemctl restart dnsmasq

if ! systemctl is-active --quiet dnsmasq; then
    echo "ERROR: dnsmasq is not active" >&2
    exit 1
fi

# ------------------------------------------------------------
# Persist final validation summary
# ------------------------------------------------------------
ARTIFACTS_JSON=$(
    find "$ARTIFACT_DIR" \
        -type f \
        -print |
        sort |
        jq -R -s '
            split("\n")
            | map(select(length > 0))
        '
)

jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg segmentation "$SEGMENTATION" \
    --arg dns_blocklist "$DNS_BLOCKLIST" \
    --argjson pipeline_exit_code "$PIPELINE_EXIT" \
    --argjson firewall_validation_exit_code "$FIREWALL_EXIT" \
    --argjson custom_rule_validation_exit_code "$CUSTOM_RULE_EXIT" \
    --argjson suricata_replays "$SURICATA_RESULTS" \
    --argjson artifacts "$ARTIFACTS_JSON" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        segmentation_rules: $segmentation,
        dns_blocklist: $dns_blocklist,
        pipeline_exit_code: $pipeline_exit_code,
        firewall_validation_exit_code: $firewall_validation_exit_code,
        custom_rule_validation_exit_code:
            $custom_rule_validation_exit_code,
        suricata_mode: "offline_replay",
        suricata_replays: $suricata_replays,
        artifacts: $artifacts,
        validation: "PASS"
    }' > "${SUMMARY}.tmp"

if ! jq empty "${SUMMARY}.tmp" >/dev/null 2>&1; then
    rm -f "${SUMMARY}.tmp"
    echo "ERROR: invalid network deployment summary" >&2
    exit 1
fi

mv "${SUMMARY}.tmp" "$SUMMARY"

echo "Network validation: PASS"
echo "Suricata PCAPs replayed: $PCAP_COUNT"
echo "Summary: $SUMMARY"

exit 0
