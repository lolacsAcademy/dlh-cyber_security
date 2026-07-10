# Kill Chains — MedDefense

## Kill Chain #1 — VPN Exploit → Full Ransomware Deployment
Actor: Ransomware/Organized crime (T6, BlackReef profile)
Target: EHR → Backup → all reachable servers
Expected Impact: Availability (encryption) + Confidentiality (exfil); financial, clinical, regulatory

Step 1 - Initial Access: Vector: VPN Exploit. Surface: External. Exploits permissive FortiGate 100F rules.
Step 2 - Foothold: Recon of AD/backups. Weakness: no SIEM/EDR, flat network allows enumeration.
Step 3 - Lateral Movement: Cred harvest (LSASS), targets DCs. Weakness: flat 10.10.2.0/24 network.
Step 4 - Objective Execution: Neutralize backups (NAS-01/backup-srv-01), deploy ransomware via GPO. All core servers encrypted.
Step 5 - Impact: Clinical (care disruption), financial ($1-3M+), regulatory (HIPAA), reputational.

Gaps Exploited: GAP-005, GAP-010, GAP-004, GAP-002
Break Points: Step 1 — harden/patch VPN (C-001). Step 3 — network segmentation (missing). Step 4 — isolated/immutable backup fixes GAP-010.
## Kill Chain #2 — Ghost Account → Insider Data Access
Actor: Insider (Malicious, T6)
Target: AD → EHR/file data
Expected Impact: Confidentiality; Integrity if altered

Step 1 - Initial Access: Vector: retained VPN account. Surface: Human/Internal. Contractor's account active 47 days post-termination.
Step 2 - Foothold: Off-hours login undetected. Weakness: no automated offboarding, no login alerting.
Step 3 - Lateral Movement: Broad account scope + flat network reaches EHR/file servers.
Step 4 - Objective Execution: Accesses/exfiltrates data via retained access.
Step 5 - Impact: Confidentiality breach, HIPAA notification, reputational/legal exposure.

Gaps Exploited: No exact Gap ID (flagged in T3) — informal offboarding gap
Break Points: Step 1 — automated deprovisioning on HR termination (missing). Step 2 — off-hours login alerting (missing).
## Kill Chain #3 — Vulnerable Software → billing-srv-01 Compromise
Actor: Unskilled/Opportunistic (T6) — already realized twice
Target: billing-srv-01
Expected Impact: Availability/Integrity — claims processing halt (4-day precedent)

Step 1 - Initial Access: Vector: Apache 2.4.29 RCE. Surface: External (port 80).
Step 2 - Foothold: Drops payload/backdoor. Weakness: EOL Ubuntu 18.04, GAP-003 controls untested.
Step 3 - Lateral Movement: Flat network + MySQL 3306 exposed network-wide enables further reach.
Step 4 - Objective Execution: Cryptominer or escalation to ransomware given repeat access.
Step 5 - Impact: Financial (claims halt), operational, reputational (3rd compromise pattern).

Gaps Exploited: GAP-003
Break Points: Step 1 — patch/replace EOL software (missing preventive). Step 2 — effective alerting control (GAP-003 explicitly missing).
## Kill Chain #4 — BEC → Fraudulent Wire Transfer
Actor: Organized crime (BEC), T6
Target: Finance/CFO process
Expected Impact: Financial loss ($85K); Integrity of the transaction

Step 1 - Initial Access: Vector: BEC, spoofed CEO email. Surface: Human.
Step 2 - Foothold: No technical foothold — urgency/secrecy substitutes. Weakness: no DMARC, no verification culture.
Step 3 - Lateral Movement: Escalation via urgency + secrecy bypasses normal approval. Weakness: no dual-approval enforced.
Step 4 - Objective Execution: CFO processes the wire transfer as instructed.
Step 5 - Impact: $85K financial loss, risk of repeat targeting.

Gaps Exploited: No dedicated Gap ID — informal finding (no DMARC/dual-approval documented)
Break Points: Step 1 — DMARC/email authentication (missing). Step 4 — mandatory callback + dual approval (missing).
## Kill Chain #5 — Supply Chain (MedTech) → Full Server Tier
Actor: Ransomware/Organized crime via vendor compromise (T6/T5)
Target: EHR/PACS/AD/Backup — whole server tier
Expected Impact: Availability + Confidentiality; same category as Chain #1, entry bypasses MedDefense's own perimeter

Step 1 - Initial Access: Vector: Supply Chain Compromise. Surface: External (vendor's environment). MedTech breached, maintenance credentials stolen.
Step 2 - Foothold: Uses MedTech's legit access to log into ehr-srv-01/db-01. Weakness: no extra MFA/monitoring on vendor sessions.
Step 3 - Lateral Movement: Flat network lets vendor's EHR-only access reach AD, backup, PACS, billing.
Step 4 - Objective Execution: Neutralize backups, exfil/deploy across entire server tier.
Step 5 - Impact: Same category as Chain #1 — clinical, financial, regulatory, reputational, worse because it bypasses MedDefense's own perimeter.

Gaps Exploited: GAP-005, GAP-010, GAP-004, GAP-002 (same downstream sequence — flat network is the common denominator)
Break Points: Step 2 — PAM/jump host limiting vendor session scope (missing, matches T5 recommendation). Step 3 — least-privilege segmentation of vendor access (missing).
