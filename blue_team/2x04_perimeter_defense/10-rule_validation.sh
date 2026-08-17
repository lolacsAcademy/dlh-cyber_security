#!/bin/bash
set -euo pipefail

RULES="./meddefense.rules"
LABELS_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
TMPDIR=$(mktemp -d)

RULE_COUNT=$(grep -c "^alert" "$RULES")
echo "[*] Loading meddefense.rules...          $RULE_COUNT rules"
echo "[*] Running validation against labeled PCAPs..."
echo ""

declare -A TARGETS
TARGETS[9000001]="meddev_egress.pcap|MEDDEV to Internet"
TARGETS[9000002]="guest_smb.pcap|Guest to SMB"
TARGETS[9000003]="large_outbound.pcap|Large Outbound From Server"
TARGETS[9000004]="dns_tunnel.pcap|DNS Tunneling Long Label"
TARGETS[9000005]="clinical_wrong_db.pcap|Clinical to Unauthorized DB"
TARGETS[9000006]="telnet_meddev.pcap|Telnet to MEDDEV"

PASSED=0
FAILED=0

for sid in 9000001 9000002 9000003 9000004 9000005 9000006; do
  IFS='|' read -r pcap_name label <<< "${TARGETS[$sid]}"
  pcap_path="$LABELS_DIR/$pcap_name"
  outdir="$TMPDIR/$sid"
  mkdir -p "$outdir"

  sudo suricata -c ./suricata.yaml -S "$RULES" -r "$pcap_path" -l "$outdir" >/dev/null 2>&1

  hits=0
  if [ -f "$outdir/eve.json" ]; then
    hits=$(sudo jq -c "select(.event_type==\"alert\" and .alert.signature_id==$sid)" "$outdir/eve.json" 2>/dev/null | wc -l)
  fi

  echo "sid $sid $label"
  echo "  target: $pcap_name"
  echo "  expected: fire"
  if [ "$hits" -gt 0 ]; then
    echo "  observed: fire ($hits hits)                PASS"
    PASSED=$((PASSED+1))
  else
    echo "  observed: no fire                          FAIL"
    FAILED=$((FAILED+1))
  fi
  echo ""
done

echo "Rules:  6"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

rm -rf "$TMPDIR"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
