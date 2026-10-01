#!/bin/bash

START="2026-05-05 08:22:17 UTC"
END="2026-05-13 06:58:45 UTC"

start_epoch=$(date -d "$START" +%s)
end_epoch=$(date -d "$END" +%s)
diff=$((end_epoch - start_epoch))

dwell=$(printf '%d days %02d:%02d:%02d' \
  $((diff / 86400)) \
  $((diff % 86400 / 3600)) \
  $((diff % 3600 / 60)) \
  $((diff % 60)))

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"

echo
echo "ATTACK TIMELINE:"

echo "  [CREDENTIAL ACCESS]"
echo "    2026-05-05 08:22:17 UTC"
echo '    WS-RECV-03: debug_tool.exe accessed lsass.exe (0x1010)'

echo
echo "  [LATERAL MOVEMENT]"
echo "    2026-05-06 07:14:33-34 UTC"
echo "    WS-RECV-03 -> SRV-HEALTH-DB using svc_healthsync"
echo "    NTLM authentication followed by PsExec"

echo
echo "  [REMOTE ACCESS]"
echo "    2026-05-06 07:48:44 UTC"
echo "    Enter-PSSession from WS-RECV-03 to SRV-HEALTH-DB"

echo
echo "  [EXPANSION]"
echo "    2026-05-09 08:42:17-18 UTC"
echo "    WS-RECV-03 -> SRV-INS-DB using svc_healthsync"
echo "    NTLM authentication followed by PsExec"

echo
echo "  [REMOTE ACCESS]"
echo "    2026-05-09 09:15:22 UTC"
echo "    Enter-PSSession from WS-RECV-03 to SRV-INS-DB"

echo
echo "  [CREDENTIAL ACCESS]"
echo "    2026-05-12 07:45:35 UTC"
echo '    WS-RECV-03: second debug_tool.exe access to lsass.exe (0x1010)'

echo
echo "  [EXPANSION]"
echo "    2026-05-13 06:58:44-45 UTC"
echo "    WS-RECV-03 -> SRV-DC-01 using svc_healthsync"
echo "    NTLM authentication followed by PsExec launching PowerShell"

echo
echo "ATTACK PROGRESSION:"
echo "  Pivot host:       WS-RECV-03"
echo "  Stolen account:   svc_healthsync"
echo "  Reached targets:  SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo "  Confirmed tools:  PsExec, PowerShell Remoting"
echo "  WMI:              Not observed from pivot host"
echo "  Copy-Item staging: Not observed"

echo
echo "UNIFIED NARRATIVE:"
echo "  Anomalous LSASS memory access occurred on WS-RECV-03 before"
echo "  unauthorized svc_healthsync NTLM authentication was observed."
echo "  The workstation then used the service account with PsExec and"
echo "  PowerShell Remoting to reach SRV-HEALTH-DB and SRV-INS-DB."
echo "  Activity later expanded to SRV-DC-01 through PsExec launching"
echo "  PowerShell. The sequence supports credential theft followed by"
echo "  service-account abuse and lateral movement."

echo
echo "DWELL TIME:"
echo "  First confirmed anomalous event: 2026-05-05 08:22:17 UTC"
echo "  Last confirmed correlated event: 2026-05-13 06:58:45 UTC"
echo "  Dwell time: $dwell"

echo
echo "ASSESSMENT:"
echo "  Status: POSITIVE - HIGH CONFIDENCE"
echo "  HEALTHBANE Stage 4 lateral movement activity is strongly supported"
echo "  by correlated credential-access, service-account abuse, PsExec and"
echo "  PowerShell Remoting evidence."
echo "  Recommendation: ESCALATE"

echo
echo "================================================================"
