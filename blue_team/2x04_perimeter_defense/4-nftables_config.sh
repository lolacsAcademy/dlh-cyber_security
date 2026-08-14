#!/bin/bash
set -euo pipefail

RULES_JSON="../segmentation_rules.json"
[ -f "$RULES_JSON" ] || RULES_JSON="segmentation_rules.json"

CONF="nftables.conf"
EVIDENCE="nftables_transition.json"

TS=$(date -u +%Y%m%d%H%M%S)
BACKUP="/var/backups/nftables-rollback-${TS}.nft"
RESTORE="/var/backups/nftables-restore-${TS}.nft"

for cmd in jq nft grep awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd" >&2
        exit 1
    fi
done

if [ ! -f "$RULES_JSON" ]; then
    echo "ERROR: segmentation_rules.json not found" >&2
    exit 1
fi

if ! jq -e '
    (.zones | type == "array") and
    (.flows | type == "array") and
    (.summary.flow_count == (.flows | length))
' "$RULES_JSON" >/dev/null; then
    echo "ERROR: invalid segmentation_rules.json" >&2
    exit 1
fi

EXPECTED_TOTAL=$(jq -r '.summary.flow_count' "$RULES_JSON")

for zone in DMZ INTERNAL MGMT MEDDEV; do
    if ! jq -e --arg zone "$zone" \
        '.zones[] | select(.name == $zone) | .cidr' \
        "$RULES_JSON" >/dev/null; then
        echo "ERROR: required zone missing: $zone" >&2
        exit 1
    fi
done

DMZ_CIDR=$(jq -r '.zones[] | select(.name == "DMZ") | .cidr' "$RULES_JSON")
INTERNAL_CIDR=$(jq -r '.zones[] | select(.name == "INTERNAL") | .cidr' "$RULES_JSON")
MGMT_CIDR=$(jq -r '.zones[] | select(.name == "MGMT") | .cidr' "$RULES_JSON")
MEDDEV_CIDR=$(jq -r '.zones[] | select(.name == "MEDDEV") | .cidr' "$RULES_JSON")

TABLE_EXISTS=0

if nft list table inet meddefense >/dev/null 2>&1; then
    TABLE_EXISTS=1
fi

: > "$CONF"

if [ "$TABLE_EXISTS" -eq 1 ]; then
    printf '%s\n\n' 'delete table inet meddefense' >> "$CONF"
fi

cat >> "$CONF" <<EOF
table inet meddefense {

  set dmz_net {
    type ipv4_addr
    flags interval
    elements = { $DMZ_CIDR }
  }

  set internal_net {
    type ipv4_addr
    flags interval
    elements = { $INTERNAL_CIDR }
  }

  set mgmt_net {
    type ipv4_addr
    flags interval
    elements = { $MGMT_CIDR }
  }

  set meddev_net {
    type ipv4_addr
    flags interval
    elements = { $MEDDEV_CIDR }
  }

  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    iifname "lo" accept

    icmp type {
      echo-request,
      echo-reply,
      destination-unreachable,
      time-exceeded
    } accept

    ip saddr @mgmt_net tcp dport 22 accept comment "MGMT_SSH_STANDING"
    ip saddr 10.0.2.2 tcp dport 22 accept comment "LAB_SSH_SAFETY"
EOF

if [ -n "${SSH_CONNECTION:-}" ]; then
    SSH_SOURCE=$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $1}')

    if [[ "$SSH_SOURCE" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf \
            '    ip saddr %s tcp dport 22 accept comment "SAFETY_ACTIVE_SSH"\n' \
            "$SSH_SOURCE" >> "$CONF"
    fi
fi

cat >> "$CONF" <<'EOF'

    udp dport 53 accept comment "LOCAL_DNS_UDP"
    tcp dport 53 accept comment "LOCAL_DNS_TCP"

    log prefix "meddefense-input-drop: " drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept
EOF

FLOW_NUMBER=0

while IFS=$'\t' read -r SRC DST PROTO DPORT JUSTIFICATION; do

    FLOW_NUMBER=$((FLOW_NUMBER + 1))

    SRC_EXPR=""
    DST_EXPR=""

    case "$SRC" in
        DMZ) SRC_EXPR="ip saddr @dmz_net" ;;
        INTERNAL) SRC_EXPR="ip saddr @internal_net" ;;
        MGMT) SRC_EXPR="ip saddr @mgmt_net" ;;
        MEDDEV) SRC_EXPR="ip saddr @meddev_net" ;;
        ALL) SRC_EXPR="" ;;
        *)
            echo "ERROR: unsupported source zone: $SRC" >&2
            exit 1
            ;;
    esac

    case "$DST" in
        DMZ) DST_EXPR="ip daddr @dmz_net" ;;
        INTERNAL) DST_EXPR="ip daddr @internal_net" ;;
        MGMT) DST_EXPR="ip daddr @mgmt_net" ;;
        MEDDEV) DST_EXPR="ip daddr @meddev_net" ;;
        INTERNET) DST_EXPR="" ;;
        *)
            echo "ERROR: unsupported destination zone: $DST" >&2
            exit 1
            ;;
    esac

    if [ "$JUSTIFICATION" = "deny_all" ]; then
        printf \
            '    %s %s drop comment "FLOW_%s"\n' \
            "$SRC_EXPR" \
            "$DST_EXPR" \
            "$FLOW_NUMBER" >> "$CONF"
        continue
    fi

    case "$PROTO" in
        tcp|udp)
            printf \
                '    %s %s %s dport %s accept comment "FLOW_%s"\n' \
                "$SRC_EXPR" \
                "$DST_EXPR" \
                "$PROTO" \
                "$DPORT" \
                "$FLOW_NUMBER" >> "$CONF"
            ;;
        *)
            echo "ERROR: unsupported allow protocol: $PROTO" >&2
            exit 1
            ;;
    esac

done < <(
    jq -r '
        .flows[] |
        [
            .src_zone,
            .dst_zone,
            .proto,
            (.dport | tostring),
            .justification
        ] |
        @tsv
    ' "$RULES_JSON"
)

cat >> "$CONF" <<'EOF'

    log prefix "meddefense-forward-drop: " drop
  }

  chain output {
    type filter hook output priority 0; policy accept;

    ip saddr @dmz_net ip daddr @meddev_net drop comment "OUTPUT_DMZ_MEDDEV_DENY"
    ip saddr @internal_net ip daddr @meddev_net drop comment "OUTPUT_INTERNAL_MEDDEV_DENY"
    ip saddr @meddev_net ip daddr @dmz_net drop comment "OUTPUT_MEDDEV_DMZ_DENY"
    ip saddr @dmz_net ip daddr @mgmt_net drop comment "OUTPUT_DMZ_MGMT_DENY"
    ip saddr @internal_net ip daddr @mgmt_net drop comment "OUTPUT_INTERNAL_MGMT_DENY"

    log prefix "meddefense-output: " counter
  }
}
EOF

echo "Rendered $CONF"

RENDERED_TOTAL=$(grep -c 'comment "FLOW_' "$CONF" || true)

if [ "$RENDERED_TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    echo "ERROR: rendered $RENDERED_TOTAL flow rules; expected $EXPECTED_TOTAL" >&2
    exit 1
fi

echo "Rendered flow rules: $RENDERED_TOTAL/$EXPECTED_TOTAL"

if ! grep -Fq \
    'ip saddr @mgmt_net tcp dport 22 accept comment "MGMT_SSH_STANDING"' \
    "$CONF"; then
    echo "ERROR: permanent MGMT SSH safety rule is missing." >&2
    exit 1
fi

if ! grep -Fq \
    'ip saddr 10.0.2.2 tcp dport 22 accept comment "LAB_SSH_SAFETY"' \
    "$CONF"; then
    echo "ERROR: lab SSH safety rule is missing." >&2
    exit 1
fi

echo "SSH safety rules: PASS"

echo "Running nft check-only validation..."

if ! nft -c -f nftables.conf; then
    echo "ERROR: nftables.conf validation failed." >&2
    exit 1
fi

echo "nftables.conf validation: PASS"

if [ "${1:-}" != "--apply" ]; then
    echo
    echo "SAFE MODE: firewall was NOT applied."
    echo "To apply after validation:"
    echo "sudo ./4-nftables_config.sh --apply"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --apply requires sudo/root." >&2
    exit 1
fi

mkdir -p /var/backups

nft list ruleset > "$BACKUP"

{
    echo "flush ruleset"
    cat "$BACKUP"
} > "$RESTORE"

if ! nft -c -f "$RESTORE"; then
    echo "ERROR: rollback ruleset failed validation." >&2
    exit 1
fi

echo "$RESTORE" > .rollback_path

jq -n \
    --arg timestamp "$TS" \
    --arg source "$RULES_JSON" \
    --arg config "$CONF" \
    --arg rollback "$BACKUP" \
    --arg restore "$RESTORE" \
    --argjson expected_rules "$EXPECTED_TOTAL" \
    --rawfile before "$BACKUP" \
    '{
        timestamp: $timestamp,
        source_rules: $source,
        rendered_config: $config,
        rollback_file: $rollback,
        restore_file: $restore,
        expected_flow_rules: $expected_rules,
        status: "pre_change_captured",
        before_ruleset: $before
    }' > "$EVIDENCE"

echo "Current ruleset backed up: $BACKUP"
echo "Rollback validation: PASS"

echo "Applying nftables.conf atomically..."

if ! nft -f nftables.conf; then
    echo "ERROR: nftables apply failed." >&2
    exit 1
fi

if ! nft list table inet meddefense >/dev/null 2>&1; then
    echo "ERROR: meddefense table verification failed." >&2
    nft -f "$RESTORE"
    echo "Previous ruleset restored." >&2
    exit 1
fi

LOADED_TOTAL=$(
    nft -a list table inet meddefense |
        grep -c 'comment "FLOW_' || true
)

if [ "$LOADED_TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    echo "ERROR: loaded $LOADED_TOTAL flow rules; expected $EXPECTED_TOTAL." >&2
    if nft -f "$RESTORE"; then
        echo "Previous ruleset restored." >&2
    else
        echo "CRITICAL: automatic rollback failed." >&2
    fi
    exit 1
fi

CURRENT_RULESET=$(nft list ruleset)

jq \
    --arg status "verified" \
    --arg verification "PASS" \
    --arg after "$CURRENT_RULESET" \
    --argjson loaded_rules "$LOADED_TOTAL" \
    '.status = $status
     | .verification = $verification
     | .loaded_flow_rules = $loaded_rules
     | .after_ruleset = $after' \
    "$EVIDENCE" > "${EVIDENCE}.tmp"

mv "${EVIDENCE}.tmp" "$EVIDENCE"

echo
echo "Verification: PASS"
echo "Expected flow rules: $EXPECTED_TOTAL"
echo "Loaded flow rules:   $LOADED_TOTAL"
echo "Evidence:            $EVIDENCE"
echo "Rollback backup:     $BACKUP"
echo "Safe restore file:   $RESTORE"
