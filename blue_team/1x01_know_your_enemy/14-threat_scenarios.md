# Three Threat Scenarios — MedDefense

## Scenario 1 — Ransomware Campaign (External)
Threat Actor: Organized crime/RaaS (BlackReef, T6)
Motivation: Financial gain
Initial Vector: VPN Exploit (T4/T8)
Attack Surface Exploited: External (T7)

Attack Sequence:
  Step 1: VPN exploit — Initial Access
  Step 2: Recon/foothold — Discovery
  Step 3: Credential harvest — Credential Access
  Step 4: Lateral movement to DC — Lateral Movement
  Step 5: Backup neutralization — Impact (Inhibit Recovery)
  Step 6: Ransomware deployment via GPO — Impact

STRIDE Categories Triggered: EHR-D1 (DoS), EHR-I1 (Disclosure), AD Elevation of Privilege, PACS-D
MedDefense Assets Impacted: ehr-srv-01/db-01, pacs-srv-01, billing-srv-01, ad-dc-01/02, backup-srv-01/NAS-01
Business Impact: Clinical (care halted), Financial ($1-3M+), Regulatory (HIPAA), Reputational (CEO-resignation precedent)
Gaps Exploited: GAP-005 (entry), GAP-010 (backup neutralized), GAP-004 (DC redundancy fails), GAP-002 (PACS permanent loss)
Detection Opportunities: Step 1 — VPN patching/IDS flags exploit. Step 3 — EDR catches LSASS dump. Step 5 — SIEM alert on backup deletion.
## Scenario 2 — Insider Data Exfiltration (Internal)
Threat Actor: Malicious insider (T3/T13 Beta pattern)
Motivation: Financial gain (selling records)
Initial Vector: Legitimate access abused (retained account, T4/T8)
Attack Surface Exploited: Human/Internal (T7)

Attack Sequence:
  Step 1: Retains legitimate access — Initial Access (Valid Accounts)
  Step 2: Assesses accessible data scope — Discovery
  Step 3: Exports records via built-in function — Collection
  Step 4: Exfiltrates via USB — Exfiltration
  Step 5: Covers tracks — Defense Evasion
  Step 6: Uses saved DB creds post-termination — Credential Access / re-entry

STRIDE Categories Triggered: EHR-R1/R2 (Repudiation), EHR-I1 (Disclosure)
MedDefense Assets Impacted: ehr-db-01, billing-srv-01, file-srv-01
Business Impact: Financial (resale/fraud losses), Regulatory (HIPAA/OCR investigation), Reputational (trust erosion if disclosed)
Gaps Exploited: No exact Gap ID (flagged repeatedly in T3/T13) — informal offboarding/DLP gaps
Detection Opportunities: Step 3 — export-volume alerting on EHR. Step 6 — automated deprovisioning prevents post-termination access entirely.
## Scenario 3 — Supply Chain Compromise (Third Party)
Threat Actor: External attacker via MedTech Solutions (T5)
Motivation: Financial gain
Initial Vector: Vendor access pathway (MedTech maintenance creds)
Attack Surface Exploited: External (vendor env) → Internal once inside (T7)

Attack Sequence:
  Step 1: Compromise MedTech's environment — Initial Access (Supply Chain Compromise)
  Step 2: Steal MedTech's maintenance credentials — Credential Access
  Step 3: Log into ehr-srv-01/db-01 via those creds — Initial Access (Valid Accounts) into MedDefense
  Step 4: Lateral movement across flat network to AD/backup/PACS/billing — Lateral Movement
  Step 5: Neutralize backups — Impact (Inhibit Recovery)
  Step 6: Deploy ransomware / exfil across entire server tier — Impact/Exfiltration

STRIDE Categories Triggered: EHR Spoofing (vendor identity abused), EHR-D1 (DoS), AD Elevation of Privilege
MedDefense Assets Impacted: ehr-srv-01/db-01, ad-dc-01/02, backup-srv-01/NAS-01, pacs-srv-01, billing-srv-01 (whole server tier)
Business Impact: Same category as Scenario 1, arguably worse — MedDefense's own perimeter controls (VPN hardening, phishing training) wouldn't have stopped it
Gaps Exploited: GAP-005, GAP-010, GAP-004, GAP-002 (same downstream sequence); entry point itself has no dedicated Gap ID
Detection Opportunities: Step 2/3 — PAM/MFA on vendor sessions flags anomalous login. Step 4 — network segmentation stops vendor's EHR-scoped access from reaching AD/backup.
