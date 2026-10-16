
# Correlated Incident Timeline: LH-2026-0414-01

Incident: IR-2026-0414-01  
User: MEDDEFENSE\dmarsh  
Timezone: UTC (ISO 8601)

## Chronological Evidence Timeline

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| 2026-04-13T18:13:44Z | Proxy log | User accessed an Outlook email immediately before the phishing-site visit. | T1566.002 | possible | proxy_log.jsonl, line 6 |
| 2026-04-13T18:14:02Z | Proxy log / SIEM | User accessed the suspicious Microsoft 365 typosquat authentication page through an email referral. | T1566.002 | confirmed | proxy_log.jsonl, line 7; A-20260414-9841 |
| 2026-04-13T18:14:41Z | Proxy log | HTTP POST submitted to the typosquat login endpoint; actual credential contents unavailable. | T1056.003 | probable | proxy_log.jsonl, line 10 |
| 2026-04-13T18:14:41Z | Azure AD | Successful Office 365 sign-in from 45.63.9.88 (RU), flagged for impossible travel. | T1078 | confirmed | ad_auth_log.jsonl, line 3 |
| 2026-04-13T18:14:43Z | Proxy log | ZIP archive downloaded from the suspicious authentication domain. | T1204.002 | confirmed | proxy_log.jsonl, line 11 |
| 2026-04-14T02:44:02Z | AD authentication | Successful Kerberos authentication for dmarsh at an unusual hour on WST-WS-031. | T1078 | confirmed | ad_auth_log.jsonl, line 5 |
| 2026-04-14T02:44:03Z | AD authentication | Successful interactive logon on WST-WS-031. | T1078 | confirmed | ad_auth_log.jsonl, line 6 |
| 2026-04-14T02:44:17Z | VPN log | Successful VPN authentication using dmarsh credentials from 45.63.9.88. | T1133, T1078 | confirmed | ad_auth_log.jsonl, line 7 |
| 2026-04-14T02:46:41Z | SIEM / EDR | Encoded PowerShell process creation reported (PID 7812). | T1059.001 | confirmed | A-20260414-9841, correlated_events[1]; ART-002-M03 pending |
| 2026-04-14T02:46:57Z | SIEM / EDR | MSBuild.exe spawned by PowerShell (PID 8104, PPID 7812); update.xml referenced in the alert. | T1127.001 | confirmed | A-20260414-9841, correlated_events[2]; ART-002-M02 pending |
| 2026-04-14T02:46:58Z | Proxy log | MSBuild-associated connection to 185.220.101.47:443, classified as a Tor exit relay. | T1071.001 | probable | proxy_log.jsonl, line 12; ART-002-M04 pending |
| 2026-04-14T02:47:11Z | SIEM alert | High-severity suspicious PowerShell-to-MSBuild process-chain alert triggered. | T1127.001 | confirmed | A-20260414-9841 |
| 2026-04-14T03:22:47Z | AD authentication | Successful Kerberos TGS request for cifs/WST-WS-017 from WST-WS-031. | T1021.002 | confirmed | ad_auth_log.jsonl, line 8 |
| 2026-04-14T03:22:48Z | AD authentication | Successful Kerberos TGS request for host/WST-WS-017. | T1021 | confirmed | ad_auth_log.jsonl, line 9 |
| 2026-04-14T03:23:01Z | AD authentication | Successful Kerberos network logon to WST-WS-017 from WST-WS-031. | T1021.002 | confirmed | ad_auth_log.jsonl, line 10 |
| 2026-04-14T03:27:13Z | Proxy log | WST-WS-017 established a proxy-recorded connection to 91.234.99.107:443, tagged as C2 infrastructure and attributed to MSBuild.exe PID 5108. | T1071.001 | probable | proxy_log.jsonl, line 15; ART-003-M02 pending |
| 2026-04-14T03:40:18Z | AD authentication | Successful Kerberos TGS request for cifs/LIS-WSIDE-01 from WST-WS-017. | T1021.002 | confirmed | ad_auth_log.jsonl, line 11 |
| 2026-04-14T03:41:52Z | AD authentication | Second successful TGS request for cifs/LIS-WSIDE-01, with ticket-reuse note. | T1021.002 | confirmed | ad_auth_log.jsonl, line 12 |
| 2026-04-14T03:42:08Z | AD authentication | Successful Kerberos network logon to LIS-WSIDE-01 from WST-WS-017. | T1021.002 | confirmed | ad_auth_log.jsonl, line 13 |
| 2026-04-14T03:43:30Z | File-server audit | Successful read-access audit covering 14 lab report PDFs in C:\LIS\reports\daily\*.pdf on LIS-WSIDE-01. | T1005 | confirmed | ad_auth_log.jsonl, line 14 |

## Required Events Without Verified Timestamps

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| Not established | Disk image ART-001 | Malicious files allegedly dropped to AppData\Local\Temp; SIEM references update.xml, but no disk extraction confirms file creation. | T1105 | possible | Task 3 filesystem_analysis.md; A-20260414-9841 |
| Not established | Disk image ART-001 | Scheduled task and Run key persistence installation not verified. | T1053.005, T1547.001 | possible | Task 4 persistence_analysis.md |
| Not established | Memory image ART-002 | NTLM hashes and Kerberos ticket material accessible in LSASS not verified. | T1003.001 | possible | Task 5 memory_analysis.md, ART-002-M07/M08 |

## Cross-Source Correlation

1. **Initial access:** Proxy records show access to a suspicious email-linked login page, followed by form submission and ZIP download. Azure AD records a risky sign-in at the same second as the form submission.

2. **Account access:** The same external IP, 45.63.9.88, appears in the risky Azure AD sign-in and later successful VPN authentication.

3. **Execution and first beacon:** SIEM-reported PowerShell and MSBuild process creation is followed by proxy connections associated with MSBuild PID 8104. Volatility confirmation remains unavailable.

4. **Movement to WST-WS-017:** Successful Kerberos service-ticket requests and network logon precede proxy-recorded connections from WST-WS-017 to infrastructure classified as C2.

5. **Access to LIS-WSIDE-01:** Kerberos service-ticket requests and network logon precede a file-server audit recording access to 14 lab report PDFs.

## Evidence Limitations

- ART-001 disk image and ART-002/ART-003 memory images were unavailable.
- Tasks 3, 4, and 5 therefore contain documented investigative gaps, not independently verified disk or memory findings.
- Proxy, authentication, EDR, and file-server records confirm their respective logged observations; malicious intent and attacker attribution require correlation.
- No forensic timestamps are invented for unverified persistence, file creation, or credential material.
- Access to 14 PDFs is documented; exfiltration is not established.
- The certainty labels apply to the described event or assessment, not automatically to every possible interpretation.

## Conclusion

The supplementary logs establish a chronological sequence from suspicious phishing-site interaction through risky authentication, VPN access, PowerShell/MSBuild execution alerts, movement between workstations, and access to 14 lab report PDFs.

Disk persistence, memory injection, and credential extraction remain unverified because the required forensic images were unavailable.
