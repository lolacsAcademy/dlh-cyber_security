#!/bin/bash

echo "================================================================"
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Period: 2026-04-14 to 2026-05-15"
echo "================================================================"

echo
echo "CHRONOLOGICAL SEQUENCE:"
echo
echo "  01  2026-04-14 13:18:05 UTC"
echo "      Diane (dmarsh) clicks credential-harvesting link on WS-RECV-03"
echo "      Target: meddefense-portal.com/login.aspx"
echo "      ATT&CK: T1566.001"
echo "      Sources: 4x00"
echo "      Confidence: CONFIRMED"

echo
echo "  02  2026-04-14 13:18:42 UTC"
echo "      Domain credentials submitted to attacker-controlled portal"
echo "      Host/User: WS-RECV-03 / dmarsh"
echo "      ATT&CK: T1078"
echo "      Sources: 4x00, 4x01"
echo "      Confidence: CONVERGED"

echo
echo "  03  2026-04-15 08:43:18 UTC"
echo "      Second-wave email E1B delivers April-Invoice-MD2026.docm"
echo "      Target: Diane / WS-RECV-03"
echo "      ATT&CK: T1566.001"
echo "      Sources: 4x01"
echo "      Confidence: CONFIRMED"

echo
echo "  04  2026-04-15 08:51:09 UTC"
echo "      DNS query for update.healthbane-c2.net -> 185.220.101.45"
echo "      Source: WS-RECV-03"
echo "      Sources: 4x01"
echo "      Confidence: CONFIRMED"

echo
echo "  05  2026-04-15 08:51:11 UTC"
echo "      svchost_update.exe RAT downloaded to WS-RECV-03"
echo "      Target: 185.220.101.45:443"
echo "      Sources: 4x01"
echo "      Confidence: CONFIRMED"

echo
echo "  06  2026-04-15 08:51:38 UTC"
echo "      First canonical HEALTHBANE C2 beacon"
echo "      Source: WS-RECV-03 -> 185.220.101.45:443"
echo "      ATT&CK: T1071.001, T1573.001"
echo "      Sources: 4x01, IR memory, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  07  2026-04-22 06:14:47 UTC"
echo "      HealthSync Run-key persistence established"
echo "      Host/User: WS-RECV-03 / records03"
echo "      ATT&CK: T1547.001"
echo "      Sources: 4x03, IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  08  2026-05-04 18:11:08 CDT"
echo "      Defender exclusion added for C:\Windows\Temp"
echo "      Host: WS-RECV-03"
echo "      Sources: IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  09  2026-05-05 03:22 CDT"
echo "      debug_tool.exe dumps LSASS; svc_healthsync harvested"
echo "      Host: WS-RECV-03"
echo "      ATT&CK: T1003.001"
echo "      Sources: 4x04, IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  10  2026-05-06 02:12 CDT"
echo "      WS-RECV-03 -> SRV-HEALTH-DB lateral movement"
echo "      Tool/Credential: PsExec + WMI/PSRemoting / svc_healthsync"
echo "      ATT&CK: T1021.002"
echo "      Sources: 4x04, IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  11  2026-05-07 01:47:33 CDT"
echo "      HealthSync Update Service scheduled task created"
echo "      Host: WS-RECV-03"
echo "      ATT&CK: T1053.005"
echo "      Sources: IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  12  2026-05-07 06:48:11 UTC"
echo "      Secondary/fallback C2 first observed"
echo "      Source: WS-RECV-03 -> 203.0.113.47:8443"
echo "      Sources: IR memory, IR firewall"
echo "      Confidence: PROBABLE"

echo
echo "  13  2026-05-08 02:36 CDT"
echo "      47,138 patient records staged from SRV-HEALTH-DB"
echo "      Destination: WS-RECV-03 / staging_export_001.zip"
echo "      ATT&CK: T1005, T1074.001, T1560.001"
echo "      Sources: IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  14  2026-05-08 07:38:14 UTC"
echo "      Patient-data exfiltration: 14,219,484 bytes"
echo "      Destination: 185.220.101.45:443"
echo "      ATT&CK: T1041"
echo "      Sources: IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  15  2026-05-09 03:01:42 CDT"
echo "      Security event log cleared; 12-minute gap"
echo "      Host: WS-RECV-03"
echo "      ATT&CK: T1070.001"
echo "      Sources: IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  16  2026-05-09 03:40 CDT"
echo "      WS-RECV-03 -> SRV-INS-DB lateral movement"
echo "      Tool/Credential: PsExec + WMI/PSRemoting / svc_healthsync"
echo "      ATT&CK: T1021.002"
echo "      Sources: 4x04, IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  17  2026-05-11 03:14 CDT"
echo "      51,002 insurance records staged from SRV-INS-DB"
echo "      Destination: WS-RECV-03 / staging_export_002.zip"
echo "      ATT&CK: T1005, T1074.001, T1560.001"
echo "      Sources: IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  18  2026-05-11 08:17:18 UTC"
echo "      Insurance-data exfiltration: 11,802,944 bytes"
echo "      Destination: 185.220.101.45:443"
echo "      ATT&CK: T1041"
echo "      Sources: IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  19  2026-05-12 02:45 CDT"
echo "      Second LSASS dump on WS-RECV-03"
echo "      ATT&CK: T1003.001"
echo "      Sources: 4x04, IR memory, IR disk"
echo "      Confidence: CONVERGED"

echo
echo "  20  2026-05-13 01:56 CDT"
echo "      WS-RECV-03 -> SRV-DC-01 lateral movement"
echo "      Tool/Credential: PsExec + PSRemoting / svc_healthsync"
echo "      Activity: Get-ADUser enumeration"
echo "      ATT&CK: T1021.002"
echo "      Sources: 4x04, IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  21  2026-05-13 02:31 CDT"
echo "      1,184 AD user/service-account records staged"
echo "      Destination: WS-RECV-03 / query_results.csv"
echo "      ATT&CK: T1074.001"
echo "      Sources: IR disk"
echo "      Confidence: SINGLE-SOURCE"

echo
echo "  22  2026-05-13 07:34:14 UTC"
echo "      AD-enumeration exfiltration: 8,419,232 bytes"
echo "      Destination: 185.220.101.45:443"
echo "      ATT&CK: T1041"
echo "      Sources: IR disk, IR firewall"
echo "      Confidence: CONVERGED"

echo
echo "  23  2026-05-15 02:00 CDT"
echo "      Final observed exfiltration attempt"
echo "      Source: WS-RECV-03"
echo "      Sources: IR team notes"
echo "      Confidence: SINGLE-SOURCE"

echo
echo "  24  2026-05-15 13:42 CDT"
echo "      WS-RECV-03 isolated; C2 traffic blocked"
echo "      Sources: IR team notes"
echo "      Confidence: CONFIRMED"

echo
echo "TIMESTAMP NORMALIZATION:"
echo "  UTC and CDT retained explicitly; CDT = UTC-5."
echo "  Firewall timestamps are 4 seconds ahead of PCAP/Wazuh."
echo "  Firewall timestamp is authoritative for connection initiation."

echo
echo "TEMPORAL METRICS:"
echo "  Total dwell time: approximately 31 days"
echo "    First access 2026-04-14 -> containment 2026-05-15."
echo "  Breakout time: approximately 21 days 18 hours"
echo "    Initial access -> first lateral movement on 2026-05-06."
echo "  Time to persistence: approximately 7 days"
echo "    Initial access -> Run-key persistence on 2026-04-22."
echo "  Time to data staging: approximately 23 days 23 hours"
echo "    Initial access -> first patient-data staging on 2026-05-08."
echo "  Detection to containment: NOT RELIABLY CALCULABLE"
echo "    4x04 records hunt initiation as 2026-05-18 09:00 CDT,"
echo "    while IR records isolation on 2026-05-15 13:42 CDT."
echo "    IR narrative also says the hunt was triggered the day before"
echo "    isolation. These supplied timestamps cannot all be reconciled."
echo "  Operational tempo:"
echo "    Intensive credential access, lateral movement, staging and"
echo "    exfiltration clustered during off-hours from May 4 through May 15."

echo
echo "TIMELINE GAPS:"
echo "  GAP 1: 2026-04-15 after C2 establishment -> 2026-04-22"
echo "    C2 remained active, but specific operator actions are not"
echo "    continuously established by the supplied evidence."
echo "  GAP 2: 2026-04-22 -> 2026-05-04"
echo "    Persistent RAT access existed, but detailed operator activity"
echo "    is not continuously observable."
echo "  GAP 3: 2026-05-14"
echo "    IR notes characterize this as a quiet day with no smoking gun."

echo
echo "SEQUENCING UNCERTAINTIES:"
echo "  [1] Hunt/detection chronology cannot be sequenced reliably because"
echo "      the supplied 4x04 and IR dates conflict."
echo "      Impact: detection-to-containment metric remains unresolved."
echo "  [2] Secondary C2 first appears on 2026-05-07, but its precise"
echo "      deployment mechanism is not established."
echo "      Impact: minimal; primary C2 chronology remains confirmed."
echo "  [3] Second LSASS dump is confirmed, but credential re-acquisition"
echo "      is assessed rather than directly demonstrated."
echo "      Impact: minimal."

echo
echo "TIMELINE SUMMARY:"
echo "  Total events: 24"
echo "  Converged events: 16"
echo "  Single-source events: 2"
echo "  Other confirmed/probable events: 6"

echo
echo "================================================================"
