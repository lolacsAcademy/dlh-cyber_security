# Task 18 — The Threat-Vulnerability Correlation

## Correlation Matrix

Finding 031 (Ghostcat) | Ransomware/RaaS | Credential/network access, vendor compromise | Chains 1 & 5 | Scenario 1 (EHR compromise step) and Scenario 3 (Supply Chain, EHR named target) | GAP-005, GAP-010, GAP-004, GAP-002

Finding 003 (PostgreSQL exposure) | Ransomware/RaaS; also Insider (Malicious/Negligent) | Credential/network access; or misuse of legitimate access | Chains 1 & 5 | Scenario 1 (EHR data); ehr-db-01 also directly named as an impacted asset in Scenario 2 | GAP-005, GAP-010, GAP-004, GAP-002 (ransomware path); Scenario 2 notes no exact Gap ID for the insider path

Finding 004 (Windows XP EOL cluster) | Ransomware/RaaS | Not the named initial vector — enables the Lateral Movement step once inside | Enables the lateral-spread phase of Chain 1 | Scenario 1, Step 4 ("Lateral movement to DC") — this device's wormable exploits are a plausible mechanism, though not explicitly named in the narrative | GAP-004

Finding 001 + 002 (billing-srv-01 chain) | Unskilled/Opportunistic | Automated scanning of unpatched public systems | Chain 3 (Vulnerable Software → billing-srv-01 Compromise) | Not one of the 3 documented T14 scenarios — matches Kill Chain 3's actor/pattern instead | GAP-003

Finding 015 (NAS-01 + CVE-2024-10441) | Ransomware/RaaS | Credential/network access | Chains 1 & 5 | Scenario 1, Step 5 ("Backup neutralization") — direct match | GAP-010

Finding 007 (LDAP relay/SMBv1) | Ransomware/RaaS (lateral movement); also Insider (Malicious) | Lateral movement post-foothold; or misuse of legitimate access | Chain 1 (lateral movement to DC) and Chain 2 (Ghost Account → Insider Data Access, names AD directly) | Scenario 1, Step 4 ("Lateral movement to DC") | GAP-004 (Chain 1 path); Chain 2 itself has no exact Gap ID

Finding 010 (BD Alaris default creds) | None of the 6 actors in the Threat Actor Matrix name Medical IoT as a primary target | N/A | None identified | None of the 3 documented scenarios include medical IoT assets | No formal Gap ID covers Medical IoT — this is itself a gap in the existing threat model, worth flagging

## Most Damaging Vulnerability

**Finding 031 (Ghostcat)** would cause the most damage when the full threat context is weighed together. It sits at the exact intersection of the highest-likelihood, highest-capability threat actor (Ransomware/RaaS), two separate documented kill chains (1 and 5), the precise narrative sequence of Scenario 1 (EHR compromise as the entry point that leads directly into backup neutralization and full ransomware deployment), and the organization's single Critical-rated top asset on every CIA pillar. Finding 015 (the backup exposure) is arguably the more catastrophic endpoint — losing backups is what turns a recoverable incident into an unrecoverable one — but in the actual documented attack sequence, Finding 031 is the door that has to open first; without this EHR foothold, the scenario's path to the backup tier doesn't exist in the first place. That combination of actor likelihood, dual kill-chain membership, a fully mapped scenario, and top-tier asset criticality makes it the single most damaging finding in the report.
