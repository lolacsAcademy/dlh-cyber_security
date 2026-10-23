
# Forensic Findings: IR-2026-0420-01

## Investigation scope and limitations

- Incident: IR-2026-0420-01
- Scope: CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112, FILE-SVR-01
- Available references: torres_call_transcript.md, proxy_72h.sample.jsonl, sysmon_multihost.sample.jsonl, fileserver_access.sample.json
- Missing investigation artifacts: cs-ws-101.mem, cs-ws-101.dd, proxy_72h.jsonl, sysmon_multihost.jsonl, fileserver_access.evtx
- Status: Partial investigation; full forensic analysis blocked by missing artifacts

The supplied sample files demonstrate event structure and representative activity. They are not substitutes for the complete investigation artifacts. No unexecuted command is represented as executed.

## ART-001 verification

- Artifact: cs-ws-101.mem
- Acquired by: Mike Torres
- Acquisition time: 2026-04-20T19:38Z
- Evidence share write time: 2026-04-20T19:41Z
- Acquisition SHA-256: Not recorded
- SHA-256 at analysis start: Not available
- Verification result: NOT VERIFIED
- Chain of custody: Acquisition documented in evidence_preservation.md; integrity verification pending

Required command:

    sha256sum cs-ws-101.mem

Result: NOT EXECUTED — memory image unavailable.

Conclusion: Memory analysis cannot begin until the artifact is obtained and its integrity limitation documented.

Certainty: confirmed (artifact unavailability in current environment).

## Memory analysis: cs-ws-101.mem

### MEM-001 — Process ancestry

Required command:

    vol -f cs-ws-101.mem windows.pstree.PsTree

Result: NOT EXECUTED — memory image unavailable.

Reference observation: Supplied Sysmon sample records WINWORD.EXE, PowerShell and svchost32.exe process creation, including parent-process relationships.

Conclusion: The sample suggests a malicious Office-to-PowerShell execution chain. Memory confirmation is pending.

ATT&CK: T1059.001 (PowerShell), T1036.005 (Match Legitimate Resource Name or Location).

Certainty: possible (full investigation not completed).

### MEM-002 — PowerShell downloader

Required command:

    vol -f cs-ws-101.mem windows.cmdline.CmdLine

Result: NOT EXECUTED — memory image unavailable.

Reference observation: The Sysmon sample contains a PowerShell command using DownloadString to retrieve inv_payload.ps1 from staging.office365-cdn.net.

Conclusion: Script-based payload retrieval is indicated by the sample; memory command-line corroboration is pending.

ATT&CK: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer).

Certainty: possible.

### MEM-003 — Active C2 connection

Required command:

    vol -f cs-ws-101.mem windows.netscan.NetScan

Result: NOT EXECUTED — memory image unavailable.

Reference observation: Sysmon sample records svchost32.exe connecting to 45.152.66.114:443 at 2026-04-20T19:32:04Z.

Conclusion: A suspicious outbound connection is recorded, but an active connection at 19:38Z has not been verified.

ATT&CK: T1071.001 (Web Protocols).

Certainty: possible.

### MEM-004 — Injected memory

Required command:

    vol -f cs-ws-101.mem windows.malfind.Malfind

Result: NOT EXECUTED — memory image unavailable.

Conclusion: Process injection cannot be confirmed.

ATT&CK: T1055 (Process Injection), hypothesis only.

Certainty: possible.

### MEM-005 — Credential material

Required command:

    vol -f cs-ws-101.mem windows.hashdump.Hashdump

Result: NOT EXECUTED — memory image unavailable.

Conclusion: NTLM hash availability and credential extraction are unverified. Any recovered credential material must be handled as sensitive evidence.

ATT&CK: T1003 (OS Credential Dumping), hypothesis only.

Certainty: possible.

## Disk analysis: cs-ws-101.dd

### DISK-001 — Partition and filesystem

Required commands:

    mmls cs-ws-101.dd
    fsstat -o <partition_start_sector> cs-ws-101.dd

Result: NOT EXECUTED — disk image unavailable.

Conclusion: Partition offsets and filesystem metadata cannot be established.

ATT&CK: Not assigned; forensic acquisition and filesystem examination.

Certainty: possible.

### DISK-002 — File activity timeline

Required commands:

    fls -r -m / -o <partition_start_sector> cs-ws-101.dd > filesystem.body
    mactime -b filesystem.body -d > filesystem_timeline.csv

Result: NOT EXECUTED — disk image unavailable.

Required review: AppData, Temp and Windows/Tasks, focusing on creation and modification timestamps.

Conclusion: Ransomware staging and file persistence cannot be established from disk.

ATT&CK: T1053.005 (Scheduled Task), investigation hypothesis only.

Certainty: possible.

### DISK-003 — Malicious file extraction

Required commands after identifying valid inode numbers:

    icat -o <partition_start_sector> cs-ws-101.dd <word_document_inode> > recovered_document.docm
    icat -o <partition_start_sector> cs-ws-101.dd <script_inode> > recovered_downloader.ps1
    icat -o <partition_start_sector> cs-ws-101.dd <beacon_dll_inode> > recovered_beacon.dll
    sha256sum recovered_document.docm recovered_downloader.ps1 recovered_beacon.dll

Result: NOT EXECUTED — disk image and inode references unavailable.

Conclusion: Original document, downloader and suspected Cobalt Strike DLL have not been extracted or independently identified.

ATT&CK: T1566.001 (Spearphishing Attachment), T1105 (Ingress Tool Transfer); hypotheses pending artifact confirmation.

Certainty: possible.

## Proxy analysis: proxy_72h.jsonl

### PROXY-001 — Initial access

Required command:

    jq -c '.' proxy_72h.jsonl | head

Result: NOT EXECUTED — complete proxy log unavailable.

Required investigation: Identify Thursday's first phishing URL access, account, source host, request method and timestamp.

Conclusion: Initial phishing access cannot be independently confirmed from the full proxy record.

ATT&CK: T1566.001 (Spearphishing Attachment), hypothesis.

Certainty: possible.

### PROXY-002 — Beacon frequency

Required command:

    jq -r '[.ts, .src_ip, .dst_ip, .dst_hostname] | @tsv' proxy_72h.jsonl

Result: NOT EXECUTED — complete proxy log unavailable; actual field names must be validated before execution.

Required investigation: Filter suspected C2 destination, sort UTC timestamps and calculate connection intervals.

Conclusion: Beacon frequency and periodicity remain undetermined.

ATT&CK: T1071.001 (Web Protocols).

Certainty: possible.

### PROXY-003 — Data staging and exfiltration

Required command:

    jq -c '.' proxy_72h.jsonl

Result: NOT EXECUTED — complete proxy log unavailable.

Required investigation: Examine unusual outbound POST requests, byte counts, destinations and transfer times.

Conclusion: No defensible exfiltration determination can be made.

ATT&CK: T1041 (Exfiltration Over C2 Channel), hypothesis only.

Certainty: possible.

## Sysmon analysis: sysmon_multihost.jsonl

### SYS-001 — Lateral movement

Required command:

    jq -c 'select(.event_id == 3 or .event_id == 1)' sysmon_multihost.jsonl

Result: NOT EXECUTED — complete Sysmon log unavailable.

Reference observation: The sample records suspicious network connections on CS-WS-104, CS-WS-107 and CS-WS-112.

Required investigation: Correlate authentication records, LogonType 3, NTLM account use, source hosts and service execution.

Conclusion: Multi-host suspicious activity is indicated, but the exact lateral movement mechanism remains unconfirmed.

ATT&CK: T1021 (Remote Services), hypothesis.

Certainty: possible.

### SYS-002 — Ransomware staging

Required command:

    jq -c 'select(.event_type == "process_create" or .event_type == "file_create")' sysmon_multihost.jsonl

Result: NOT EXECUTED — complete Sysmon log unavailable.

Required investigation: Identify cmd.exe or powershell.exe writing .bat or .ps1 files into system directories.

Conclusion: Ransomware staging is not confirmed.

ATT&CK: T1059.003 (Windows Command Shell), T1059.001 (PowerShell); hypotheses.

Certainty: possible.

### SYS-003 — Suspicious service installation

Required command:

    jq -c 'select(.event_type == "registry_set" or .event_type == "process_create")' sysmon_multihost.jsonl

Result: NOT EXECUTED — complete Sysmon log unavailable.

Reference observation: The sample records WinHealthSvc pointing to C:\ProgramData\Microsoft\svchost32.exe on CS-WS-101. Torres reported SIEM rule wz-edr-200214 on three additional workstations.

Conclusion: Suspicious service persistence is supported by reference evidence but requires full event correlation.

ATT&CK: T1543.003 (Windows Service), T1036.005 (Match Legitimate Resource Name or Location).

Certainty: probable.

## File server analysis: fileserver_access.evtx

### FILE-001 — Patient documentation access

Required command:

    evtx_dump -o json fileserver_access.evtx > fileserver_access_full.json

Result: NOT EXECUTED — complete EVTX unavailable.

Reference observation: The supplied sample describes an access window from 2026-04-19T02:14:01Z to 02:41:12Z and references 1,847 Event ID 4663 rows in the full export.

Required investigation: Count actual records, group by file path and UTC access time, and correlate account names with successful authentication events.

Conclusion: The sample reports a patient-file access window, but the full 1,847 records have not been independently counted or categorized. Access alone does not prove exfiltration.

ATT&CK: T1005 (Data from Local System), investigation hypothesis.

Certainty: possible.

## Attack chain summary

| Stage | UTC timestamp / range | ATT&CK technique | Hosts | Evidence | Certainty |
|---|---|---|---|---|---|
| Suspected malicious document execution | 2026-04-17 14:17–14:22Z | T1566.001, T1059.001 | CS-WS-101 | Sysmon sample | possible |
| Payload download and execution | 2026-04-17 14:22–14:23Z | T1105, T1059.001 | CS-WS-101 | Sysmon sample | possible |
| Suspicious service persistence | 2026-04-17 14:23Z | T1543.003 | CS-WS-101 | Sysmon sample | probable |
| Suspected C2 communication | 2026-04-17 to 2026-04-20 | T1071.001 | CS-WS-101, 104, 107, 112 | Sysmon sample | possible |
| Suspected lateral movement | 2026-04-19 | T1021 | CS-WS-104, 107, 112 | Sysmon sample; Torres transcript | possible |
| Patient documentation access | 2026-04-19 02:14–02:41Z | T1005 | FILE-SVR-01 | File-server sample | possible |
| Possible ransomware activity | 2026-04-20, before 19:43Z | Not confirmed | CS-WS-101 | Torres transcript | possible |

## Final assessment

The available references indicate a potentially serious multi-host intrusion involving suspicious PowerShell execution, service persistence, outbound communications and possible access to patient documentation.

The complete attack chain, active memory state, injected code, recovered malware, credential theft, ransomware staging and exfiltration remain unverified.

This report is preliminary. Full forensic conclusions require the original memory image, disk image, complete proxy and Sysmon logs, and full file-server EVTX, together with documented integrity verification.
