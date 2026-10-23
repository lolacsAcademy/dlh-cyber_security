
# Evidence Preservation: IR-2026-0420-01

## Priority Order Rationale

Evidence acquisition begins before containment, with parallel collection where personnel and tools permit. Priority reflects volatile memory, possible ransomware staging, command-and-control activity, credential exposure, and patient documentation access.

1. **CS-WS-101:** Initial compromise host; Torres already captured memory at 19:38Z. Prioritize disk imaging to preserve possible ransomware staging, persistence, and original files.
2. **CS-WS-104:** Suspected lateral compromise and C2 activity. Capture memory first to preserve processes, connections, and possible credentials.
3. **CS-WS-107:** Suspected lateral compromise and C2 activity. Capture memory before isolation.
4. **FILE-SVR-01:** Preserve file-access audit records and disk evidence relating to patient documentation. Protect clinical availability during acquisition.
5. **CS-WS-112:** Suspected lateral compromise. Preserve memory, logon evidence, and disk after higher-priority captures.

Sysmon records show outbound connections from all four workstations to 45.152.66.114:443. The supplied records do not prove that each connection remained active at acquisition time. The order is an operational priority, not a requirement to delay parallel collection.

## ART-001: cs-ws-101.mem — Existing Acquisition

- host: CS-WS-101
- acquired_by: Mike Torres
- acquired_at: 2026-04-20T19:38:00Z
- tool: WinPmem
- evidence_path: \\evidence\share\IR-2026-0420-01\cs-ws-101.mem
- written_to_share_at: 2026-04-20T19:41:00Z
- sha256_at_acquisition: Not recorded
- sha256_verified_by_analyst: Pending
- verification_command: `Get-FileHash -Algorithm SHA256 <evidence_path>`
- custody_status: Existing acquisition; verification required before analysis
- gap_note: Three minutes elapsed between memory acquisition and writing to the evidence share. Torres called at 19:43:18Z, approximately five minutes after acquisition. Incident declaration occurred at 19:52Z, fourteen minutes after acquisition. No acquisition-time hash exists for comparison; compute and preserve the first available baseline hash and document this limitation.

## ART-002: cs-ws-101.dd

- host: CS-WS-101
- priority: 1
- acquisition: Planned; not yet evidenced
- tool: FTK Imager via authorized IR jumpbox
- method: Acquire forensic disk image with verification enabled before host containment, subject to patient-safety authorization
- additional_evidence: Windows Event Logs, Sysmon, registry hives, scheduled tasks, services, and suspected encryption artifacts
- verification: Calculate SHA-256 using `Get-FileHash -Algorithm SHA256 <image_path>`; compare against acquisition verification hash
- custody: Record operator, UTC start/end, source disk, destination, hash, transfer, and evidence custodian

## ART-003: cs-ws-104.mem / cs-ws-104.dd

- host: CS-WS-104
- priority: 2
- acquisition: Planned; not yet evidenced
- tool: WinPmem for RAM; FTK Imager for disk
- method: Capture memory before network isolation; acquire verified disk image
- volatile_evidence: Running processes, network connections, loaded modules, services, and possible credential material
- additional_commands:
  - `Get-NetTCPConnection`
  - `Get-Process`
  - `Get-CimInstance Win32_Service`
  - `wevtutil epl Microsoft-Windows-Sysmon/Operational <export_path>`
  - `wevtutil epl Security <export_path>`
- verification: `Get-FileHash -Algorithm SHA256 <artifact_path>` for every acquired artifact
- custody: Record operator, UTC timestamps, original source, destination, hash, and each transfer

## ART-004: cs-ws-107.mem / cs-ws-107.dd

- host: CS-WS-107
- priority: 3
- acquisition: Planned; not yet evidenced
- tool: WinPmem for RAM; FTK Imager for disk
- method: Capture volatile memory and connection state before isolation; then acquire disk image
- volatile_evidence: Suspected C2 processes, network connections, and credential material
- additional_commands:
  - `Get-NetTCPConnection`
  - `Get-Process`
  - `wevtutil epl Microsoft-Windows-Sysmon/Operational <export_path>`
  - `wevtutil epl Security <export_path>`
- verification: `Get-FileHash -Algorithm SHA256 <artifact_path>`; compare against acquisition baseline
- custody: Record operator, UTC timestamps, source, destination, hash, and transfers

## ART-005: file-svr-01.dd / file-svr-01-security.evtx

- host: FILE-SVR-01
- priority: 4
- acquisition: Planned; not yet evidenced
- tool: FTK Imager and Windows Event Log export
- method: Preserve access logs immediately; coordinate disk imaging or forensic snapshot with clinical IT before service-impacting operations
- commands:
  - `wevtutil epl Security <export_path>`
  - `wevtutil epl Microsoft-Windows-Sysmon/Operational <export_path>`
  - `Get-FileHash -Algorithm SHA256 <artifact_path>`
- evidence_focus: Patient documentation access, Event ID 4663, access window 2026-04-19T02:14:01Z to 02:41:12Z
- limitation: Supplied JSON is a condensed sample, not the complete 1,847-event EVTX export
- custody: Record source log/image, collector, UTC time, hash, secure destination, and transfers

## ART-006: cs-ws-112.mem / cs-ws-112.dd

- host: CS-WS-112
- priority: 5
- acquisition: Planned; not yet evidenced
- tool: WinPmem for RAM; FTK Imager for disk
- method: Capture memory before isolation, then preserve disk and authentication evidence
- commands:
  - `Get-NetTCPConnection`
  - `Get-Process`
  - `wevtutil epl Security <export_path>`
  - `wevtutil epl Microsoft-Windows-Sysmon/Operational <export_path>`
- verification: `Get-FileHash -Algorithm SHA256 <artifact_path>`; compare against acquisition baseline
- custody: Record operator, UTC timestamps, source, destination, hash, and transfers

## Integrity and Handling Requirements

- Use approved forensic tools and secure evidence storage.
- Record UTC acquisition and transfer timestamps.
- Hash each artifact at acquisition and verify after transfer.
- Do not claim successful verification without matching recorded hashes.
- Do not analyze ART-001 until its available-copy integrity check is recorded.
- Preserve original evidence read-only where technically possible.
- Document any unavoidable interruption or patient-safety exception.
- Do not isolate clinical hosts without authorized operational impact assessment.

## Chain of Custody

| Artifact | Host | Collector | Acquisition UTC | Tool | SHA-256 / Verification | Status |
|---|---|---|---|---|---|---|
| ART-001 | CS-WS-101 | Mike Torres | 2026-04-20 19:38Z | WinPmem | Acquisition hash absent; analyst baseline pending | Acquired; verification pending |
| ART-002 | CS-WS-101 | Assigned forensic analyst | Pending | FTK Imager | Pending | Planned |
| ART-003 | CS-WS-104 | Assigned forensic analyst | Pending | WinPmem / FTK Imager | Pending | Planned |
| ART-004 | CS-WS-107 | Assigned forensic analyst | Pending | WinPmem / FTK Imager | Pending | Planned |
| ART-005 | FILE-SVR-01 | Assigned forensic analyst | Pending | EVTX export / FTK Imager | Pending | Planned |
| ART-006 | CS-WS-112 | Assigned forensic analyst | Pending | WinPmem / FTK Imager | Pending | Planned |

All future acquisitions and custody transfers must be appended with the actual UTC time, person, evidence location, SHA-256, and verification result. No pending action is represented as completed.
