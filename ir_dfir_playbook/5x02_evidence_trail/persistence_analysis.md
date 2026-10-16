
# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact Verification

- Case: LH-2026-0414-01
- Artifact: ART-001
- Hash at analysis start: Unavailable
- Baseline verification: Pending
- CoC entry updated: No; artifact not accessed
- Status: Analysis pending; disk image unavailable

## Registry Persistence

### Run and RunOnce Keys

- Evidence ID: ART-001-R01
- Hive: NTUSER.DAT (dmarsh profile)
- Keys:
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
- Value name: Not available
- Value data: Not available
- Last write: Unknown
- Significance: These keys can launch programs at user logon. No suspicious entry has been confirmed.

### Scheduled Tasks

- Evidence ID: ART-001-R02
- Path: C:\Windows\System32\Tasks\
- Task XML: Not extracted
- Trigger: Unknown
- Action: Unknown
- Principal: Unknown
- Last write: Unknown
- Significance: Scheduled tasks may provide persistence through automatic execution. No malicious task has been confirmed.

## Execution Evidence

### UserAssist

- Evidence ID: ART-001-E01
- Hive: C:\Users\dmarsh\NTUSER.DAT
- Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
- Value name: Not extracted
- Decoded value: Not available
- Run count: Unknown
- Last executed: Unknown
- Last write: Unknown
- Significance: UserAssist can provide evidence of user-interactive program launches. No execution has been confirmed from this source.

### AppCompatCache / ShimCache

- Evidence ID: ART-001-E02
- Hive: C:\Windows\System32\config\SYSTEM
- Registry data: AppCompatCache
- Executable path: Unknown
- Entry order: Unknown
- Last write: Unknown
- Significance: ShimCache may show executables observed by Windows. Presence alone does not prove execution.

### Amcache

- Evidence ID: ART-001-E03
- Path: C:\Windows\AppCompat\Programs\Amcache.hve
- Executable: Unknown
- SHA-1: Not available
- First execution timestamp: Not established
- Last write: Unknown
- Significance: Amcache can provide executable metadata and timestamps. Interpretation depends on the Windows version and recorded fields.

### Recent LNK Files

- Evidence ID: ART-001-E04
- Path: C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\
- LNK file: Not extracted
- Target path: Unknown
- MAC times: Unknown
- Last write: Unknown
- Significance: Shortcut files may identify files accessed by the user. No targets have been verified.

## SIEM Correlation

- Alert ID: A-20260414-9841
- Host: WST-WS-031
- User: MEDDEFENSE\dmarsh
- Reported parent process: powershell.exe
- Reported child process: MSBuild.exe
- Reported file: C:\Users\dmarsh\AppData\Local\Temp\update.xml
- Assessment: SIEM indicators only; registry and disk confirmation pending.

## Analysis Limitations

- The disk image wst-ws-031.dd was not included in the downloaded lab materials.
- No registry hives could be extracted or mounted.
- No scheduled task XML files or LNK files could be examined.
- No SHA-256 baseline verification could be performed.
- No persistence mechanism or execution event is independently confirmed.
- Original evidence must remain protected under litigation hold LH-2026-0414-01.

## Conclusion

Persistence and execution evidence remain unverified because ART-001 is unavailable.

All six required artifact categories have been identified for examination. No forensic findings have been fabricated.
