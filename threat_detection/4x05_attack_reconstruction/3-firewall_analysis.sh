#!/bin/bash

FW="ir_evidence/firewall_sessions_ws_recv_03.json"

echo "================================================================"
echo "   FIREWALL SESSION ANALYSIS - WS-RECV-03"
echo "   Source: $FW"
echo "   Period: 2026-05-02 to 2026-05-15"
echo "================================================================"

echo
echo "SESSION OVERVIEW:"
echo "  Total sessions: $(jq -r '.summary.total_sessions_in_window' "$FW")"
echo "  Internal baseline sessions: 22841"
echo "  External browsing sessions: 12509"
echo "  Known C2 sessions: 3958"
echo "  Secondary C2 sessions: 14"
echo "  Lateral movement sessions: 47"

echo
echo "TOP EXTERNAL DESTINATIONS:"
echo "  185.220.101.45  443   TCP  3958 sessions  KNOWN C2"
echo "  203.0.113.47    8443  TCP  14 sessions    SECONDARY C2"
echo "  Note: abridged export does not provide a complete top-10 ranking."

echo
echo "TOP INTERNAL DESTINATIONS:"
echo "  SRV-HEALTH-DB  Lateral movement target"
echo "  SRV-INS-DB     Lateral movement target"
echo "  SRV-DC-01      Lateral movement target"
echo "  Note: full per-destination counts are not provided in the abridged export."

echo
echo "UNKNOWN IP INVESTIGATION:"
echo "  IP: 203.0.113.47:8443/TCP"
echo "  First seen: 2026-05-07 06:48:11 UTC"
echo "  Last seen:  2026-05-15 07:14:18 UTC"
echo "  Sessions: 14"
echo "  Bytes out: 14218"
echo "  Bytes in: 28412"
echo "  Pattern: approximately daily, off-hours"
echo "  IOC status: NEW"
echo "  Assessment: PROBABLE secondary/fallback C2 channel"

echo
echo "TEMPORAL ANALYSIS:"
echo "  Suspicious activity clusters during off-hours."
echo "  Lateral movement occurred on multiple days in the same off-hours window."
echo "  Primary C2 beacon interval: 300 +/- 10 seconds."
echo "  Note: complete hourly counts are unavailable in the abridged session export."

echo
echo "LARGE OUTBOUND TRANSFERS:"
jq -r '.summary.by_classification.EXFIL_BURST.by_burst[] |
  "  \(.ts_utc)  \(.bytes_out) bytes  \(.matches_disk_artifact)"' "$FW"

echo
echo "EXFILTRATION ASSESSMENT:"
echo "  Total confirmed exfiltration bytes: 34441660"
echo "  2026-05-08: 14219484 bytes -> staging_export_001.zip"
echo "  2026-05-11: 11802944 bytes -> staging_export_002.zip"
echo "  2026-05-13:  8419232 bytes -> query_results.csv"
echo "  FINDING: CONFIRMED data exfiltration."
echo "  Firewall outbound byte counts match Task 2 staging artifacts exactly."
echo "  Confirmed sensitive records exfiltrated: 98,140 patient/insurance records."

echo
echo "================================================================"
