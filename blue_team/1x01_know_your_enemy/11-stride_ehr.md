# STRIDE on the EHR — MedDefense

## SPOOFING
### EHR-S1
Description: Harvested clinician creds (vishing, T4 Sc.3) used to log into EHR as that clinician
Vector: Vishing/Phishing (T8)
Impact: Unauthorized actions attributed to real clinician; record integrity risk
Control: C-012 exists, MFA not confirmed
Gap: No dedicated Gap ID

### EHR-S2
Description: Attacker on flat network spoofs ehr-db-01 to intercept/redirect PostgreSQL traffic (MITM)
Vector: Unsecure Networks (T8)
Impact: Credential/query interception, silent data manipulation possible
Control: None documented
Gap: Underlies flat-network gap pattern (no direct ID)

## TAMPERING
### EHR-T1
Description: Direct PostgreSQL access (5432 open to /16) used to modify patient records, bypassing app logic/audit trail
Vector: Open Service Ports (T8)
Impact: Falsified dosage/allergy/diagnosis data — direct patient safety risk
Control: None — port not restricted
Gap: No dedicated Gap ID

### EHR-T2
Description: Physical access to server room used to tamper with ehr-srv-01 application files directly
Vector: Physical Access (T8/T9)
Impact: Silently altered application logic, hidden backdoor
Control: Generic badge only, no camera (A-23)
Gap: Related to GAP-005 pattern
## REPUDIATION
### EHR-R1
Description: Shared/borrowed credentials mean a record edit can't be tied to one person, who then denies it
Vector: Default/Shared Credentials pattern (T8)
Impact: No defensible accountability record — legal/clinical risk
Control: C-008 passive logging, no per-action attribution
Gap: No dedicated Gap ID

### EHR-R2
Description: Actions via a compromised ghost account (T3 Sc.2) get attributed to the departed employee, who can truthfully deny it
Vector: Insider/Ghost account pattern (T3)
Impact: Incident response delay, unclear accountability during breach
Control: None — no automated offboarding
Gap: No exact Gap ID (flagged in T3/T10)

## INFORMATION DISCLOSURE
### EHR-I1
Description: PostgreSQL 5432 open to the entire /16 lets any compromised device query ehr-db-01 directly, no app-layer controls
Vector: Open Service Ports (T8)
Impact: Mass patient data exposure
Control: None
Gap: No dedicated Gap ID (matches T8/T9)

### EHR-I2
Description: Compromised workstation on the flat segment sniffs/queries EHR traffic meant for other users
Vector: Unsecure Networks (T8)
Impact: Bulk in-transit patient data exposure
Control: None — segmentation absent org-wide
Gap: Underlies GAP-005/010 pattern
## DENIAL OF SERVICE
### EHR-D1
Description: Ransomware (T2/T10 Chain #1) encrypts ehr-srv-01/db-01 directly, EHR fully unavailable clinic-wide
Vector: VPN Exploit → ransomware
Impact: Care delivery halted, forced paper charting
Control: Backup is single point of failure
Gap: GAP-010, GAP-002

### EHR-D2
Description: Exposed PostgreSQL port flooded with connections/queries, exhausting DB resources, no app-tier breach needed
Vector: Open Service Ports (T8)
Impact: EHR outage during active care hours
Control: None — no rate limiting/WAF on the DB port
Gap: No dedicated Gap ID
## ELEVATION OF PRIVILEGE
### EHR-E1
Description: Compromised low-priv workstation → credential harvesting (LSASS, T2 pattern) → Domain Admin → self-granted EHR DB rights
Vector: Credential harvesting + flat network (T8/T9)
Impact: Full administrative control of the EHR platform, not one record
Control: C-012 alone doesn't stop credential dumping
Gap: GAP-004 (AD-adjacent); no dedicated EHR-specific ID

### EHR-E2
Description: Registration clerk (T4 Sc.4 pattern) uses lack of RBAC to view/edit clinical records outside her role scope
Vector: Insider (Malicious) / access-control gap (T3 Sc.4)
Impact: Unauthorized clinical data access at will
Control: None — no RBAC/least-privilege documented
Gap: No dedicated Gap ID (flagged in T3 Sc.4)

## STRIDE Summary
Information Disclosure is the greatest risk to this specific system: PostgreSQL 5432 being open to the entire /16 is an already-confirmed, unauthenticated-adjacent path straight to the full patient database, requiring no sophistication beyond having any foothold on that range. In a healthcare context this is especially dangerous because disclosed patient data can't be "patched" after the fact — unlike an encrypted system that can be restored, once records are exposed the harm is permanent and the HIPAA/regulatory consequences are automatic and severe.
