
# Evidence Preservation Runbook: IR-2026-0414-01

**Incident:** IR-2026-0414-01  
**Severity:** SEV2  
**Endpoint:** WST-WS-031 (West Campus Laboratory)  
**Account:** MEDDEFENSE\dmarsh  
**Alert:** A-20260414-9841, 2026-04-14T02:47:11Z  
**Evidence store:** `/evidence/IR-2026-0414-01/`  
**Hash algorithm:** SHA-256

## Preparation — Before containment

Run `evidence_store_init.sh` once from the supplied materials:

```bash
bash ~/Downloads/5x01/evidence_store_init.sh
```

The script creates the evidence subdirectories and initializes `hashes.txt`. Do not rerun it against an existing incident directory.

Use these variables for the Linux commands below:

```bash
STORE=/evidence/IR-2026-0414-01
SRC="$HOME/Downloads/5x01"
```

Record the analyst, UTC acquisition time, source system, capture method, and any errors in the incident timeline. Restrict evidence-store access to authorized responders.

**Preservation order:** Memory first, followed by live process and network state, then endpoint and centralized logs. Do not kill processes, reboot, reset credentials, or isolate the endpoint before collecting volatile evidence unless an immediate safety risk requires an exception approved by the incident commander.

## 1. Volatile memory — WST-WS-031

- **What:** Full physical memory, including potentially injected code, credentials, and active process state.
- **How:** On WST-WS-031, run an approved WinPmem executable as Administrator:

```powershell
.\winpmem_3.3.rc3.exe -o C:\IRCapture\wst-ws-031.mem
```

- **Where:** Transfer the resulting file using the approved evidence-transfer mechanism to `/evidence/IR-2026-0414-01/memory/wst-ws-031.mem`.
- **Hash:** Calculate SHA-256 on the Windows source before transfer:

```powershell
certutil -hashfile C:\IRCapture\wst-ws-031.mem SHA256
```

After transfer, calculate and record the destination hash using the Linux manifest procedure below. Compare both values.

- **Ordering:** Capture before terminating PID 7204 (`update.exe`), PID 7812 (`powershell.exe`), or PID 8104 (`MSBuild.exe`). Process termination or reboot could destroy relevant memory.
- **Caution:** The supplied lab files do not include a live Windows endpoint or memory image. Do not claim acquisition succeeded without an actual capture.

## 2. Running processes and parent-child relationships

- **What:** Active processes, PIDs, parent PIDs, executable paths, and command lines.
- **How:** Run on WST-WS-031 in an elevated PowerShell session:

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
  Export-Csv C:\IRCapture\processes.csv -NoTypeInformation
```

- **Where:** `/evidence/IR-2026-0414-01/process_tree/processes.csv`
- **Hash:** SHA-256 after transfer, recorded in `hashes.txt`.
- **Ordering:** Run immediately after memory acquisition, before process termination. Confirm whether PIDs 7204, 7812, and 8104 remain active; do not assume they do.

## 3. Active network connections

- **What:** Current TCP connections, local and remote endpoints, connection states, and owning PIDs.
- **How:** Run on WST-WS-031:

```powershell
Get-NetTCPConnection |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv C:\IRCapture\network_connections.csv -NoTypeInformation
```

- **Where:** `/evidence/IR-2026-0414-01/network/network_connections.csv`
- **Hash:** SHA-256 after transfer.
- **Ordering:** Capture before network isolation. The alert records MSBuild PID 8104 communicating with `185.220.101.47:443`; isolation may terminate that connection.

## 4. Full endpoint telemetry — Previous 24 hours

- **What:** WazuhEDR events for WST-WS-031, including process creation, file changes, persistence, memory indicators, and network connections.
- **How:** Preserve the supplied endpoint export without modifying its contents:

```bash
cp "$SRC/edr_wst_ws_031_24h.jsonl" "$STORE/endpoint_telemetry/"
```

- **Where:** `/evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`
- **Hash:** SHA-256 in `hashes.txt`.
- **Ordering:** Preserve before any EDR cleanup, endpoint remediation, or telemetry-retention expiry.
- **Scope:** Verify the export covers the 24 hours preceding `2026-04-14T02:47:11Z`. The supplied file is the lab export; do not describe it as a newly collected live EDR response.

## 5. SIEM alert record

- **What:** Original WazuhEDR alert JSON, including detection rule, process tree, host, user, network activity, and threat-intelligence enrichment.
- **How:**

```bash
cp "$SRC/alert_A-20260414-9841.json" "$STORE/siem/"
```

- **Where:** `/evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json`
- **Hash:** SHA-256 in `hashes.txt`.
- **Ordering:** Preserve the original alert before enrichment, case updates, or response actions change the investigation context.

## 6. Proxy and DNS records — dmarsh

- **What:** Proxy requests and DNS-resolution activity associated with dmarsh and WST-WS-031 during the 24 hours preceding the alert.
- **How — supplied proxy export:**

```bash
cp "$SRC/proxy_24h_dmarsh.log" "$STORE/proxy_dns/"
```

- **Where:** `/evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log`
- **Hash:** SHA-256 in `hashes.txt`.
- **Ordering:** Preserve before log rotation or retention expiry.

The proxy export records access to `ms0365-support.login-verification.click`, an HTTP POST to `/auth/submit`, download of `update.zip`, and connections to `185.220.101.47:443`.

**DNS gap:** The supplied proxy file does not contain DNS query/response records. Request the separate DNS resolver or SIEM export for dmarsh and source IP `10.42.118.31`, covering `2026-04-13T02:47:11Z` through `2026-04-14T02:47:11Z`. Save the native export as `proxy_dns/dns_24h_dmarsh.json`, then hash it. Record it as pending if unavailable; do not fabricate DNS evidence.

## 7. Authentication records — Active Directory and Azure AD

- **What:** Domain-controller authentication and Azure AD sign-in events for dmarsh over the 24-hour investigation window.
- **How:**

```bash
cp "$SRC/auth_24h_dmarsh.json" "$STORE/authentication/"
```

- **Where:** `/evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json`
- **Hash:** SHA-256 in `hashes.txt`.
- **Ordering:** Preserve before credential resets, session revocation, or authentication-log retention expiry.

The export identifies AD sources `ms-dc01` and `ms-dc02` plus Azure AD. It includes a successful Azure AD sign-in from `45.63.9.88`, flagged `impossibleTravel` at `2026-04-13T18:14:41Z`. This requires investigation; it does not independently establish credential theft.

## 8. SHA-256 manifest and verification

After each file is transferred or copied, append its destination hash to the initialized manifest.

Run from the Kali evidence-store environment:

```bash
cd "$STORE"
find memory process_tree network endpoint_telemetry siem proxy_dns authentication \
  -type f -print0 | sort -z | xargs -0 -r sha256sum > capture_hashes.tmp
cat capture_hashes.tmp >> hashes.txt
rm capture_hashes.tmp
```

**Important:** Run the manifest-generation command only once after the current acquisition batch. For later additions, append only the new file's hash, for example:

```bash
sha256sum proxy_dns/dns_24h_dmarsh.json >> hashes.txt
```

The initialized `hashes.txt` contains chain-of-custody comments. Each artifact entry uses the format:

`<SHA-256>  <relative_path>`

**Final verification:**

```bash
cd "$STORE"
sha256sum -c hashes.txt
```

- Every captured artifact must report `OK`.
- Compare transferred Windows artifacts against their original Windows SHA-256 values.
- Record missing files, hash mismatches, collection failures, or unavailable DNS evidence as `OBSERVATION` entries in `incident_timeline.md`.
- Do not silently replace mismatched evidence or overwrite original captures.
- Record the final verification time and analyst identity in the incident timeline.

**Containment gate:** Proceed to containment only after available volatile evidence has been captured, required exports have been preserved and hashed, and any gaps or emergency exceptions have been documented.
