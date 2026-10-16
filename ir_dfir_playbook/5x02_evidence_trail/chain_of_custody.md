
# Chain of Custody: LH-2026-0414-01

## Case Header

- **Case number:** LH-2026-0414-01
- **Incident ID:** IR-2026-0414-01
- **Lead investigator:** Forensic Analyst
- **Date opened:** 2026-04-14
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z

## Artifact Registry

| Artifact ID | Artifact Name | Format | Acquired By | Acquisition Timestamp (UTC) | Acquisition Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ART-001 | wst-ws-031.dd | RAW/dd | Mike Torres | 2026-04-14T06:14Z | FTK Imager | Not computed at acquisition | Evidence share: IR-2026-0414-01; exact path unverified | Not documented; read-only access required |
| ART-002 | wst-ws-031.mem | RAW memory | Mike Torres | 2026-04-14T03:02Z | WinPmem v3.3-rc3 | Not computed at acquisition | Evidence share: IR-2026-0414-01; exact path unverified | Not documented; read-only access required |
| ART-003 | wst-ws-017.mem | RAW memory | Mike Torres | 2026-04-14T03:38Z | WinPmem | Not computed at acquisition | Evidence share: IR-2026-0414-01; exact path unverified | Not documented; read-only access required |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified (yes/no) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-04-14, time not recorded | Mike Torres | ART-001 | read_write_mount | Windows Explorer | no | Pre-imaging filesystem access reported by acquirer. Possible metadata changes. |
| 2026-04-14T07:42Z | Mike Torres | ART-001, ART-002, ART-003 | acquisition_handoff_report | Acquisition notes | no | Acquisition and handling gaps disclosed. Actual handoff time not documented. |

## Evidence Integrity and Handling Rules

- Litigation hold applies to all three artifacts.
- Preserve original evidence without modification or deletion.
- Establish SHA-256 baseline hashes before first forensic analysis access.
- Acquisition hashes are unavailable and must not be reconstructed or invented.
- Perform forensic analysis on verified working copies.
- Append every subsequent access to this log with timestamp, actor, artifact, action, tool, hash verification, and notes.
- Record any hash mismatch immediately as DEVIATION.

## Known Evidence Gaps

- No SHA-256 hashes were recorded at acquisition.
- No contemporaneous chain-of-custody log exists.
- Physical and network access before handoff was not documented.
- The live filesystem of WST-WS-031 was mounted read-write before disk acquisition.
- Disk acquisition started at 04:51Z and finished at 06:14Z, after VLAN 999 isolation.
- Exact evidence storage paths and access permissions remain unverified.
- The three forensic images are not available in the current Kali environment; baseline hashing remains pending.
