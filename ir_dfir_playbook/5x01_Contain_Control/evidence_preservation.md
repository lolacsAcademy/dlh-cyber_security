
# Evidence Preservation Runbook: IR-2026-0414-01

**Incident:** IR-2026-0414-01  
**Severity:** SEV2  
**Endpoint:** WST-WS-031, West Campus Laboratory  
**Account:** MEDDEFENSE\dmarsh  
**Alert:** A-20260414-9841, fired 2026-04-14T02:47:11Z  
**Evidence store:** `/evidence/IR-2026-0414-01/`  
**Hash algorithm:** SHA-256  
**Manifest:** `/evidence/IR-2026-0414-01/hashes.txt`

## Preparation

Execute the supplied initialization script once:

```bash
bash ~/Downloads/5x01/evidence_store_init.sh
```

It creates the incident evidence directories and initializes `hashes.txt`. If the store already exists, do not reinitialize or overwrite it.

On the Kali evidence workstation, set:

```bash
STORE=/evidence/IR-2026-0414-01
SRC="$HOME/Downloads/5x01"
cd "$STORE"
```

For each artifact, record the analyst, UTC capture time, source system, original filename, acquisition method, and transfer result in the incident timeline.

**Order:** Capture memory, live processes, and live network connections first. Then preserve endpoint telemetry, SIEM alerts, proxy logs, DNS logs, and authentication events. Complete hashing and verification before containment.

Do not terminate processes, reboot, disconnect the workstation, reset credentials, or revoke sessions before the relevant volatile evidence is preserved, unless an immediate safety requirement overrides this sequence.

## 1. Volatile memory — WST-WS-031

**What:** Full physical memory containing running process state, possible injected code, and transient credential material.

**How:** On WST-WS-031, run approved WinPmem as Administrator:

```powershell
New-Item -ItemType Directory -Force C:\IRCapture
.\winpmem_3.3.rc3.exe -o C:\IRCapture\wst-ws-031.mem
certutil -hashfile C:\IRCapture\wst-ws-031.mem SHA256
```

Transfer the memory image using the approved secure evidence-transfer mechanism.

**Where:** `/evidence/IR-2026-0414-01/memory/wst-ws-031.mem`

**Hash command on Kali:**

```bash
sha256sum memory/wst-ws-031.mem >> hashes.txt
```

Compare this destination hash with the original Windows SHA-256 value.

**Ordering rationale:** Memory is captured first because terminating `update.exe` (PID 7204), `powershell.exe` (PID 7812), or `MSBuild.exe` (PID 8104) could destroy in-memory evidence. Rebooting would also invalidate the original memory state. Memory acquisition must precede process termination and endpoint remediation.

## 2. Running process list and process tree

**What:** Running processes, PIDs, parent PIDs, executable paths, and full command lines.

**How:** On WST-WS-031, run elevated PowerShell:

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
Export-Csv C:\IRCapture\processes.csv -NoTypeInformation
certutil -hashfile C:\IRCapture\processes.csv SHA256
```

Transfer `processes.csv` securely to the evidence store.

**Where:** `/evidence/IR-2026-0414-01/process_tree/processes.csv`

**Hash command:**

```bash
sha256sum process_tree/processes.csv >> hashes.txt
```

Compare source and destination hashes.

**Ordering rationale:** Capture immediately after memory and before any process kill. This preserves the live relationship between `update.exe`, PowerShell, and MSBuild. Process termination could remove active PID and parent-child information before network capture or containment.

## 3. Active network connections

**What:** Live TCP connections, local and remote addresses, ports, connection states, and owning process IDs.

**How:** On WST-WS-031, run elevated PowerShell:

```powershell
Get-NetTCPConnection |
Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
Export-Csv C:\IRCapture\network_connections.csv -NoTypeInformation
certutil -hashfile C:\IRCapture\network_connections.csv SHA256
```

Transfer the CSV securely to the evidence store.

**Where:** `/evidence/IR-2026-0414-01/network/network_connections.csv`

**Hash command:**

```bash
sha256sum network/network_connections.csv >> hashes.txt
```

Compare source and destination hashes.

**Ordering rationale:** Capture after the process list so owning PIDs can be correlated, but before network isolation. The alert records MSBuild PID 8104 connecting to `185.220.101.47:443`. Isolation may close active connections and destroy their live state.

## 4. Endpoint telemetry — WST-WS-031

**What:** WazuhEDR events for the 24 hours before the alert, including process execution, persistence, file modifications, network activity, and suspicious memory regions.

**How:** Preserve the supplied export:

```bash
cp "$SRC/edr_wst_ws_031_24h.jsonl" endpoint_telemetry/
```

**Where:** `/evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`

**Hash command:**

```bash
sha256sum endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> hashes.txt
```

**Ordering rationale:** Capture after live endpoint state because the existing telemetry export is less volatile than active memory, processes, or connections. Preserve before EDR retention expiry, remediation, or any cleanup that could remove local telemetry.

## 5. SIEM alert — A-20260414-9841

**What:** Original JSON alert, including rule `wz-edr-100041`, host identity, process tree, network connection, and threat-intelligence enrichment.

**How:**

```bash
cp "$SRC/alert_A-20260414-9841.json" siem/
```

**Where:** `/evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json`

**Hash command:**

```bash
sha256sum siem/alert_A-20260414-9841.json >> hashes.txt
```

**Ordering rationale:** Capture after live endpoint evidence and before modifying SIEM case records or detection configuration. The original alert must remain available for later comparison with the incident timeline and endpoint telemetry.

## 6. Proxy logs — dmarsh

**What:** HTTP and HTTPS proxy activity associated with `dmarsh` and source IP `10.42.118.31`, covering the 24 hours before the alert.

**How:**

```bash
cp "$SRC/proxy_24h_dmarsh.log" proxy_dns/
```

**Where:** `/evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log`

**Hash command:**

```bash
sha256sum proxy_dns/proxy_24h_dmarsh.log >> hashes.txt
```

**Ordering rationale:** Preserve after live endpoint captures and before proxy-log rotation or expiration. The export helps establish the sequence from the suspicious Microsoft-themed login page to the ZIP download and later outbound communication.

## 7. DNS logs — dmarsh / WST-WS-031

**What:** DNS queries and responses for `WST-WS-031` (`10.42.118.31`) during `2026-04-13T02:47:11Z` through `2026-04-14T02:47:11Z`, especially lookups associated with `ms0365-support.login-verification.click`.

**How:** In the organization's authorized DNS/SIEM console:

1. Select the DNS resolver log dataset.
2. Filter the UTC time range above.
3. Filter client IP `10.42.118.31`.
4. Export all matching DNS events in native JSON format.
5. Transfer the export securely to the evidence store.

Use the filename `dns_24h_dmarsh.json`.

**Where:** `/evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.json`

**Hash command:**

```bash
sha256sum proxy_dns/dns_24h_dmarsh.json >> hashes.txt
```

**Ordering rationale:** Collect after live endpoint state and the proxy export, but before DNS log rotation or retention expiry. DNS records may reveal additional resolved infrastructure not visible in HTTP proxy records and help validate the domain-to-IP relationship.

**Source limitation:** No DNS export was included in the supplied lab materials. This is the required acquisition procedure, not a claim that the DNS file already exists. If the export is unavailable, document the collection failure in the incident timeline and do not invent the file or its hash.

## 8. Authentication logs — Active Directory and Azure AD

**What:** Authentication events for `MEDDEFENSE\dmarsh` / `dmarsh@meddefense.local`, including AD domain-controller activity and Azure AD sign-ins during the 24 hours before the alert.

**How:**

```bash
cp "$SRC/auth_24h_dmarsh.json" authentication/
```

**Where:** `/evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json`

**Hash command:**

```bash
sha256sum authentication/auth_24h_dmarsh.json >> hashes.txt
```

**Ordering rationale:** Preserve after volatile endpoint evidence and network-related logs, but before credential resets, session revocation, or authentication-log retention expiry. These records help investigate the Azure AD `impossibleTravel` signal at `2026-04-13T18:14:41Z` without assuming credential theft is confirmed.

## 9. Final evidence verification

Every successfully acquired artifact must have one SHA-256 entry in the incident manifest, using the format:

`<sha256>  <relative_path>`

**Verify the evidence store:**

```bash
cd /evidence/IR-2026-0414-01
sha256sum -c hashes.txt
```

Expected result: `OK` for every listed artifact.

Also compare the original Windows SHA-256 values for memory, processes, and network connections against their destination hashes.

**Completeness check:**

- Memory image captured and hashed.
- Process tree captured and hashed.
- Network connections captured and hashed.
- Endpoint telemetry preserved and hashed.
- SIEM alert JSON preserved and hashed.
- Proxy export preserved and hashed.
- DNS export acquired and hashed, or its unavailability explicitly recorded.
- AD and Azure AD authentication export preserved and hashed.

Record the verification timestamp, analyst identity, and results in `incident_timeline.md`.

For missing artifacts, failed acquisitions, or hash mismatches, append an `OBSERVATION` entry. Never overwrite original evidence or silently replace a failed capture.

**Containment gate:** Begin containment only after available volatile evidence has been captured, required log exports have been preserved, hashes have been verified, and any unresolved evidence gaps have been documented.
