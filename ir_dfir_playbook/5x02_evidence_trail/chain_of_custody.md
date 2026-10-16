
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
| ART-001 | wst-ws-031.dd | RAW | Mike Torres | 2026-04-14 06:14Z | FTK Imager | Not computed | Evidence share; exact path to verify | To verify |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14 03:02Z | WinPmem v3.3-rc3 | Not computed | Evidence share; exact path to verify | To verify |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14 03:38Z | WinPmem | Not computed | Evidence share; exact path to verify | To verify |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified (yes/no) | Notes |
| --- | --- | --- | --- | --- | --- | --- |

## Known Evidence Gaps

- No SHA-256 hashes were computed at acquisition.
- No original chain-of-custody log was maintained.
- Physical and network access before SOC hand-off was not recorded.
- WST-WS-031 was mounted read-write before disk imaging. Filesystem metadata may have changed.
- Baseline SHA-256 hashes must be established before analysis.
- All subsequent access events must be appended to the access log.
- Any hash mismatch must be recorded immediately as DEVIATION.
- Original artifacts must remain preserved under the litigation hold.
