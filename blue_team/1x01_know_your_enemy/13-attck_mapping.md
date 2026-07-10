# ATT&CK Mapping — MedDefense

## SCENARIO ALPHA — Operation Flatline

### Step 1 — Purchase org list from IAB
Tactic: Resource Development
Technique: Acquire Access (T1650)
MedDefense Factor: FortiGate scannable/identifiable from internet, put MedDefense on the broker's list

### Step 2 — Spear phishing + macro→PowerShell
Tactic: Initial Access
Technique: Phishing: Spearphishing Link (T1566.002); alt: User Execution (T1204.002) + PowerShell (T1059.001)
MedDefense Factor: Sarah Park targeted directly, opens doc on WS-HQ-01

### Step 3 — Persistent backdoor via scheduled task
Tactic: Persistence
Technique: Scheduled Task (T1053.005); alt: C2 — Application Layer Protocol (T1071.001)
MedDefense Factor: No EDR to catch a disguised scheduled task

### Step 4 — Network discovery (nltest, net group, arp)
Tactic: Discovery
Technique: Domain Trust Discovery (T1482); alt: Permission Groups Discovery: Domain (T1069.002), Remote System Discovery (T1018)
MedDefense Factor: Flat network + HQ↔Central VPN = entire /16 visible from one workstation
### Step 5 — Mimikatz dumps cached creds
Tactic: Credential Access
Technique: LSASS Memory (T1003.001)
MedDefense Factor: svc_backup admin hash cached from a prior session

### Step 6 — Pass-the-hash to ad-dc-01
Tactic: Lateral Movement
Technique: Pass the Hash (T1550.002)
MedDefense Factor: No segmentation between workstation and DC

### Step 7 — pg_dump + Rclone exfil to cloud
Tactic: Exfiltration
Technique: Exfil to Cloud Storage (T1567.002)
MedDefense Factor: PostgreSQL 5432 open, no extra auth, no alerting

### Step 8 — Delete backups + VSS shadows
Tactic: Impact
Technique: Inhibit System Recovery (T1490)
MedDefense Factor: Backup single point of failure (GAP-010)

### Step 9 — GPO ransomware deployment
Tactic: Impact
Technique: Data Encrypted for Impact (T1486); alt: Group Policy Modification (T1484.001)
MedDefense Factor: Flat AD-managed environment, one GPO hits everything
## SCENARIO BETA — The Quiet Departure

### Step 1 — Maria decides to steal data
Tactic: Initial Access
Technique: Valid Accounts (T1078)
MedDefense Factor: Standing legit billing + EHR read-only access

### Step 2 — Assesses what data she can view
Tactic: Discovery
Technique: No distinct technique — authorized scope assessment
MedDefense Factor: No session record limit or unusual-volume alert

### Step 3 — Exports ~200 records/day via CSV
Tactic: Collection
Technique: Data from Information Repositories (T1213)
MedDefense Factor: Export function open to all read-access users, no extra auth

### Step 4 — Copies CSVs to personal USB
Tactic: Exfiltration
Technique: Exfil Over Physical Medium: USB (T1052.001)
MedDefense Factor: No USB restriction GPO
### Step 5 — Deletes CSVs, empties recycle bin
Tactic: Defense Evasion
Technique: Indicator Removal: File Deletion (T1070.004)
MedDefense Factor: EHR audit log exists but needs 48h vendor export, never reviewed

### Step 6 — Copies DB creds from config file
Tactic: Credential Access
Technique: Credentials In Files (T1552.001)
MedDefense Factor: Billing app stores DB creds in plaintext config on workstation

### Step 7 — VPN access not revoked for 5 days
Tactic: Persistence
Technique: Valid Accounts (T1078)
MedDefense Factor: No SLA/automated deactivation tied to HR termination

### Step 8 — Reconnects post-termination, pulls 400 more records
Tactic: Initial Access
Technique: External Remote Services (T1133); alt: Collection (T1213)
MedDefense Factor: VPN creds still valid 3 days after last day

## ATT&CK Coverage Assessment
Initial Access, Credential Access, and Exfiltration appear in both scenarios — a sophisticated ransomware affiliate and an ordinary insider both succeeded through the same blind spots: standing/unrevoked access, unprotected credentials, and unmonitored data egress. MedDefense's most urgent detection need isn't actor-specific — it's credential-access and exfiltration monitoring, since both attacks walked through the exact same gaps.
