
# Gap Analysis: IR-2026-0414-01

## Gap Register

| Gap ID | Phase | Gap description | Control category | Recommended improvement | Priority | Linked findings |
|---|---|---|---|---|---|---|
| GAP-001 | Credential phishing and submission | MedDefense allowed access to the phishing domain. | Preventive | Block `ms0365-support.login-verification.click` in the web proxy and add phishing-domain filtering. | P1 critical | Task 1 phase 1 |
| GAP-002 | Credential phishing and submission | Stolen credentials remained usable. | Preventive | Enforce phishing-resistant FIDO2 MFA for MedDefense accounts. | P1 critical | Task 1 phase 1 |
| GAP-003 | VPN access from a foreign IP | VPN access from IP `45.63.9.88` was not blocked. | Preventive | Apply VPN conditional access rules blocking unapproved countries and risky sign-ins. | P1 critical | Task 1 phase 2 |
| GAP-004 | VPN access from a foreign IP | Azure AD risk signals were suppressed by the compliant-device rule. | Detective | Review the compliant-device exception and enable risky sign-in alerts. | P1 critical | Forensic summary: open investigative items |
| GAP-005 | PowerShell to MSBuild execution | Malicious MSBuild execution was not prevented. | Preventive | Configure Microsoft Defender ASR rules and WDAC restrictions for unapproved MSBuild execution. | P2 high | ART-002-M01 |
| GAP-006 | PowerShell to MSBuild execution | Malicious files established Run-key and scheduled-task persistence. | Detective | Add Microsoft Defender alerts for suspicious Run-key changes and scheduled-task creation. | P2 high | ART-001-R01, ART-001-R02 |
| GAP-007 | C2 beaconing | Both compromised hosts connected to external C2 addresses. | Preventive | Block `185.220.101.47` and `91.234.99.107` at the egress firewall. | P2 high | ART-002-M02, ART-003-M01 |
| GAP-008 | LSASS access and Kerberos ticket extraction | Credential material was exposed in LSASS. | Preventive | Enable Windows Credential Guard and LSASS protected-process settings. | P1 critical | ART-002-M04 |
| GAP-009 | LSASS access and Kerberos ticket extraction | Effective Kerberos abuse detection was not documented. | Detective | Alert on abnormal Kerberos ticket requests using Windows Event ID 4769. | P2 high | Task 1 phase 5 |
| GAP-010 | Lateral movement and PHI access | Compromised credentials reached other hosts and 14 patient reports. | Preventive | Restrict `LIS_REPORTS$` permissions and segment workstation-to-server access. | P1 critical | ART-003-M01, AD-LOG-01 |

## Priority summary

- **GAP-001 (P1):** Blocking the phishing domain could prevent initial credential theft.
- **GAP-002 (P1):** Phishing-resistant MFA reduces the risk of stolen credentials being reused.
- **GAP-003 (P1):** VPN access restrictions could block suspicious foreign-origin authentication.
- **GAP-004 (P1):** Restoring risk signals improves detection of suspicious sign-ins.
- **GAP-008 (P1):** LSASS protection reduces exposure of credential material.
- **GAP-010 (P1):** Access restrictions limit lateral movement and exposure of patient records.
