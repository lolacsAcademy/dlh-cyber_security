
# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

## Artifact Verification

- Case: LH-2026-0414-01
- ART-002 SHA-256: Not available; baseline pending
- ART-003 SHA-256: Not available; baseline pending
- CoC entries updated: No; memory images not accessed
- Status: Analysis pending; memory images unavailable

## wst-ws-031.mem Findings

### ART-002-M01: Process List

Command:
`vol -f wst-ws-031.mem windows.pslist.PsList`

- Output: Not available
- PID/PPID: Not independently verified
- Finding: Process creation times and running processes cannot be established.
- Significance: Required to identify suspicious processes.
- Certainty: Unverified
- ATT&CK: Not assigned

### ART-002-M02: Process Tree

Command:
`vol -f wst-ws-031.mem windows.pstree.PsTree`

- Output: Not available
- SIEM-reported PIDs: powershell.exe (7812), MSBuild.exe (8104)
- Finding: Parent-child relationship not verified in memory.
- Significance: SIEM reports PowerShell launching MSBuild.
- Certainty: Possible, based on SIEM context only
- ATT&CK: T1127.001, T1059.001

### ART-002-M03: Command Lines

Command:
`vol -f wst-ws-031.mem windows.cmdline.CmdLine`

- Output: Not available
- PID: Not independently verified
- Finding: Command-line arguments could not be extracted.
- Significance: SIEM references update.xml as an MSBuild argument.
- Certainty: Possible, based on SIEM context only
- ATT&CK: T1127.001

### ART-002-M04: Network Connections

Command:
`vol -f wst-ws-031.mem windows.netscan.NetScan`

- Output: Not available
- SIEM-reported destination: 185.220.101.47:443
- Owning PID: Not verified
- Finding: No memory-based network connection confirmed.
- Significance: Investigate possible command-and-control activity.
- Certainty: Possible, based on SIEM context only
- ATT&CK: T1071.001

### ART-002-M05: MSBuild DLLs

Command:
`vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104`

- Output: Not available
- PID: 8104 (SIEM-reported; unverified)
- Finding: Loaded DLLs could not be examined.
- Significance: May identify unexpected modules loaded by MSBuild.
- Certainty: Unverified
- ATT&CK: Not assigned

### ART-002-M06: Suspicious Memory Regions

Command:
`vol -f wst-ws-031.mem windows.malfind.Malfind`

- Output: Not available
- PID: Not independently verified
- Finding: No executable memory regions examined.
- Significance: Required to investigate possible process injection.
- Certainty: Unverified
- ATT&CK: T1055 (investigation target only)

### ART-002-M07: LSASS Handles

Command:
`vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid>`

- Output: Not available
- LSASS PID: Unknown
- Finding: LSASS handles could not be inspected.
- Significance: May help identify suspicious access involving credential processes. Handle evidence requires careful interpretation.
- Certainty: Unverified
- ATT&CK: T1003.001 (investigation target only)

### ART-002-M08: Credential Hashes

Command:
`vol -f wst-ws-031.mem windows.hashdump.Hashdump`

- Output: Not available
- PID: Not applicable
- Finding: No credential hashes extracted.
- Significance: Credential exposure cannot be determined.
- Certainty: Unverified
- ATT&CK: T1003.002 (investigation target only)

## wst-ws-017.mem Findings

### ART-003-M01: Process List

Command:
`vol -f wst-ws-017.mem windows.pslist.PsList`

- Output: Not available
- PID/PPID: Unknown
- Finding: No process list extracted.
- Certainty: Unverified
- ATT&CK: Not assigned

### ART-003-M02: Network Connections

Command:
`vol -f wst-ws-017.mem windows.netscan.NetScan`

- Output: Not available
- PID: Unknown
- Finding: No network connections extracted.
- Certainty: Unverified
- ATT&CK: Not assigned

### ART-003-M03: Command Lines

Command:
`vol -f wst-ws-017.mem windows.cmdline.CmdLine`

- Output: Not available
- PID: Unknown
- Finding: No command-line arguments extracted.
- Certainty: Unverified
- ATT&CK: Not assigned

## SIEM Correlation

- Alert: A-20260414-9841
- Host: WST-WS-031
- Reported activity: powershell.exe launched MSBuild.exe
- Reported destination: 185.220.101.47:443
- Assessment: These are SIEM indicators, not independent memory findings.
- Memory confirmation: Pending

## Analysis Limitations

- Neither memory image was included in the supplied lab ZIP.
- No SHA-256 baseline could be established.
- No Volatility plugin was executed against the memory images.
- No process, network, injection, or credential findings are independently confirmed.
- Memory analysis must not begin until artifact integrity is verified.

## Conclusion

Memory-based investigation remains pending because ART-002 and ART-003 are unavailable.

All required Volatility 3 plugins and their investigative purposes are documented. No memory results have been fabricated.
