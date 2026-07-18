# Task 10 — The Risk Register

MedDefense Health Systems — top 10 risks. Likelihood/Impact: 1-5 scale (1=Rare/Negligible, 5=Almost Certain/Severe).

## RISK-001

```yaml
Description: "Ransomware destroys production and backup together."
Category: "Operational"
Threat Source: "Ransomware/RaaS"
Vulnerability: "None direct — Breach 1/Alpha correlation"
Asset: "Backup & Storage — Critical"
Likelihood: "3"
Impact: "5"
Inherent Score: "15"
ALE: "$468,300"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Highest ALE, low-cost fix"
Planned Control: "Offsite backup replication"
Residual Risk: "$46,830 — Low"
KRI: "Days since last backup restore test"
Review Date: "Oct 2026"
```

## RISK-002

```yaml
Description: "Attacker steals VPN credentials, reaches full network."
Category: "Operational"
Threat Source: "Ransomware/RaaS, Kill Chain 1"
Vulnerability: "FortiGate OSINT (1x02)"
Asset: "VPN/FortiGate — Critical"
Likelihood: "3"
Impact: "5"
Inherent Score: "15"
ALE: "$375,550"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Cheapest control, breaks top access vector"
Planned Control: "MFA on VPN/admin accounts"
Residual Risk: "$53,650 — Low"
KRI: "% admin/VPN accounts with MFA"
Review Date: "Oct 2026"
```

## RISK-003

```yaml
Description: "Ransomware encrypts EHR via flat network."
Category: "Operational"
Threat Source: "Ransomware/RaaS, Kill Chain 1"
Vulnerability: "Finding 003, 031 (1x02)"
Asset: "EHR system — Critical"
Likelihood: "3"
Impact: "5"
Inherent Score: "15"
ALE: "$370,800"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Contains blast radius for every other risk"
Planned Control: "Network segmentation Phase 1"
Residual Risk: "$111,240 — Medium"
KRI: "# critical assets reachable from other subnets"
Review Date: "Oct 2026"
```

## RISK-004

```yaml
Description: "Negligent staff expose patient data — no DLP, no training."
Category: "Compliance"
Threat Source: "Negligent Insider"
Vulnerability: "None scanned — 280 workstations, no DLP"
Asset: "Clinical workstations"
Likelihood: "5"
Impact: "3"
Inherent Score: "15"
ALE: "$300,000"
Owner: "Deputy CISO (James Chen)"
Treatment: "Accept (for now)"
Justification: "Not funded this cycle — no DLP budget line yet"
Planned Control: "None funded — Phase 2 candidate"
Residual Risk: "$300,000 — unchanged, High"
KRI: "# USB write events/month"
Review Date: "Jan 2027"
```

## RISK-005

```yaml
Description: "Malware runs undetected for weeks, no logging."
Category: "Operational"
Threat Source: "Ransomware/cryptomining"
Vulnerability: "billing-srv-01 findings (1x02)"
Asset: "billing-srv-01 — High"
Likelihood: "5"
Impact: "2"
Inherent Score: "10"
ALE: "$106,800"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate (deferred)"
Justification: "Positive value, deferred one cycle for labor bandwidth"
Planned Control: "SIEM (Wazuh) — next fiscal year"
Residual Risk: "$53,400 until funded — Medium"
KRI: "Mean time to detect (MTTD)"
Review Date: "Jan 2027"
```

## RISK-006

```yaml
Description: "Infusion pumps compromised via default credentials."
Category: "Operational"
Threat Source: "Opportunistic attacker"
Vulnerability: "BD Alaris CVE (1x00 T7)"
Asset: "Infusion pumps (7 units) — Critical"
Likelihood: "1"
Impact: "5"
Inherent Score: "5"
ALE: "$62,100"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Low likelihood, catastrophic patient-safety impact"
Planned Control: "Credential reset + device isolation/monitoring"
Residual Risk: "$15,525 — Low"
KRI: "# pumps still on default credentials"
Review Date: "Oct 2026"
```

## RISK-007

```yaml
Description: "Secondary domain controller has no backup."
Category: "Operational"
Threat Source: "Ransomware/RaaS"
Vulnerability: "None direct — ad-dc-01 findings as context"
Asset: "ad-dc-02 — Critical"
Likelihood: "3"
Impact: "4"
Inherent Score: "12"
ALE: "N/A — contributes to RISK-001"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Cheap fix, funded from $32,500 reserve"
Planned Control: "Extend backup to ad-dc-02"
Residual Risk: "Low once extended"
KRI: "Backup success rate, ad-dc-02"
Review Date: "Jan 2027"
```

## RISK-008

```yaml
Description: "PACS server excluded from backup."
Category: "Operational"
Threat Source: "Ransomware/RaaS"
Vulnerability: "None direct — 1x00 Task 10 matrix"
Asset: "pacs-srv-01 — Critical"
Likelihood: "3"
Impact: "4"
Inherent Score: "12"
ALE: "N/A — contributes to RISK-001"
Owner: "Deputy CISO (James Chen)"
Treatment: "Mitigate"
Justification: "Cheap fix, funded from $32,500 reserve"
Planned Control: "Add pacs-srv-01 to backup schedule"
Residual Risk: "Low once extended"
KRI: "Backup success rate, pacs-srv-01"
Review Date: "Jan 2027"
```

## RISK-009

```yaml
Description: "Shared PACS login removes accountability."
Category: "Compliance"
Threat Source: "Insider (malicious/negligent)"
Vulnerability: "None direct — 1x00 Task 10"
Asset: "PACS / Medical Imaging — Critical"
Likelihood: "3"
Impact: "3"
Inherent Score: "9"
ALE: "N/A"
Owner: "Deputy CISO + Radiology Dept Head (Data Owner)"
Treatment: "Mitigate"
Justification: "Low-cost account fix, funded from reserve"
Planned Control: "Individual accounts replace shared login"
Residual Risk: "Low once deployed"
KRI: "# active shared accounts on PACS"
Review Date: "Jan 2027"
```

## RISK-010

```yaml
Description: "Network closet has weak badge access, no camera."
Category: "Operational"
Threat Source: "Insider / physical intruder"
Vulnerability: "None — physical, outside scan scope"
Asset: "Network Closet / Core — Critical"
Likelihood: "3"
Impact: "4"
Inherent Score: "12"
ALE: "N/A"
Owner: "IT Director (Sarah Park)"
Treatment: "Mitigate"
Justification: "Cheap physical fix, funded from reserve"
Planned Control: "Camera + keycard audit trail"
Residual Risk: "Low once installed"
KRI: "# unauthorized closet access events"
Review Date: "Jan 2027"
```

---

## Register Summary

| ID | Description | Score | ALE | Treatment | Review |
|---|---|---|---|---|---|
| RISK-001 | Backup destroyed with production | 15 | $468,300 | Mitigate | Oct 2026 |
| RISK-002 | VPN compromise, no MFA | 15 | $375,550 | Mitigate | Oct 2026 |
| RISK-003 | Ransomware encrypts EHR | 15 | $370,800 | Mitigate | Oct 2026 |
| RISK-004 | Negligent insider exposure | 15 | $300,000 | Accept | Jan 2027 |
| RISK-005 | Undetected malware dwell time | 10 | $106,800 | Mitigate (deferred) | Jan 2027 |
| RISK-006 | Infusion pump compromise | 5 | $62,100 | Mitigate | Oct 2026 |
| RISK-007 | ad-dc-02 no backup | 12 | N/A | Mitigate | Jan 2027 |
| RISK-008 | PACS excluded from backup | 12 | N/A | Mitigate | Jan 2027 |
| RISK-009 | Shared PACS login | 9 | N/A | Mitigate | Jan 2027 |
| RISK-010 | Network closet exposure | 12 | N/A | Mitigate | Jan 2027 |

## Governance Note

The Deputy CISO (James Chen) owns this register; the Security Analyst updates it as controls land or new findings appear. Reviewed quarterly. Out-of-cycle review triggers: a confirmed incident on a listed asset, a new critical vulnerability disclosure, or a KRI breaching threshold. On a KRI breach, the Risk Owner escalates to the Deputy CISO within 48 hours, that entry is rescored immediately, and the CEO is briefed if the score rises into Critical range (per Task 4's RACI).
