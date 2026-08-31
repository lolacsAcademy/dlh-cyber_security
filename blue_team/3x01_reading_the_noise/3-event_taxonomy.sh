#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
INPUT="$HANDOFF_DIR/data/enriched_events.json"

cat > event_taxonomy.json <<'EOF'
[
{"source_type":"windows_json","match":{"event_id":"4624"},"label":"login_success"},
{"source_type":"windows_json","match":{"event_id":"4625"},"label":"login_failure"},
{"source_type":"windows_json","match":{"event_id":"4634"},"label":"logout"},
{"source_type":"windows_json","match":{"event_id":"4740"},"label":"account_lockout"},
{"source_type":"windows_json","match":{"event_id":"4672"},"label":"privilege_escalation"},
{"source_type":"windows_json","match":{"event_id":"1"},"label":"process_start"},
{"source_type":"windows_json","match":{"event_id":"23"},"label":"process_stop"},
{"source_type":"linux_text","match":{"event_category":"SYSCALL"},"label":"child_process_spawn"},
{"source_type":"linux_text","match":{"event_category":"PATH"},"label":"file_read_sensitive"},
{"source_type":"windows_json","match":{"event_id":"11"},"label":"file_write_sensitive"},
{"source_type":"windows_json","match":{"event_id":"4670"},"label":"file_permission_change"},
{"source_type":"windows_json","match":{"event_id":"3"},"label":"network_connection_outbound"},
{"source_type":"windows_json","match":{"event_id":"5156"},"label":"network_connection_inbound"},
{"source_type":"linux_text","match":{"event_category":"suricata"},"label":"network_alert"},
{"source_type":"windows_json","match":{"event_id":"5157"},"label":"network_blocked"}
]
EOF

jq -c '
  .canonical_label =
    if .event_id=="4624" then "login_success"
    elif .event_id=="4625" then "login_failure"
    elif .event_id=="4634" then "logout"
    elif .event_id=="4740" then "account_lockout"
    elif .event_id=="4672" then "privilege_escalation"
    elif .event_id=="1" then "process_start"
    elif .event_id=="23" then "process_stop"
    elif .event_category=="SYSCALL" then "child_process_spawn"
    elif .event_category=="PATH" then "file_read_sensitive"
    elif .event_id=="11" then "file_write_sensitive"
    elif .event_id=="4670" then "file_permission_change"
    elif .event_id=="3" then "network_connection_outbound"
    elif .event_id=="5156" then "network_connection_inbound"
    elif .event_category=="suricata" then "network_alert"
    elif .event_id=="5157" then "network_blocked"
    else "unlabeled" end
' "$INPUT" > labeled_events.json

RULES=$(jq 'length' event_taxonomy.json)
LABELED=$(grep -vc '"canonical_label":"unlabeled"' labeled_events.json)
UNLABELED=$(grep -c '"canonical_label":"unlabeled"' labeled_events.json)

echo "taxonomy rules         : $RULES"
echo "records labeled        : $LABELED"
echo "records unlabeled      : $UNLABELED"
echo "canonical label distribution (top 10):"
jq -r '.canonical_label' labeled_events.json | sort | uniq -c | sort -nr | head -10
echo "event_taxonomy.json written"
echo "labeled_events.json written"
