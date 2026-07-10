# Vector-to-Asset Matrix — MedDefense

Columns: EHR, PACS, Backup, Billing-srv-01, Network Core, Medical IoT, AD.
Note: no "Top 5 Critical Assets" file from 1x00 T8 was provided — used Critical-rated assets from the Gap Analysis instead.

## Phishing/Spear Phishing
- EHR: creds → flat net → PostgreSQL 5432 open → ehr-db-01
- PACS: creds → flat net → pacs-srv-01
- Backup: creds → flat net → NAS-01 mgmt ports exposed
- Billing: invoice macro → RAT → billing-srv-01 (BlackReef pattern)
- IoT: creds → flat net → IoT web interfaces
- AD: creds → LSASS dump on workstation → Domain Admin

## VPN Exploit
- EHR/PACS/Backup/Billing/IoT/AD: FortiGate exploit → flat internal net → all reachable (T2 Phase 1)

## Default/Shared Credentials
- PACS: raduser/radiology1 shared login → direct access, no attribution (GAP-008)

## Vulnerable Software Exploit
- Billing: Apache 2.4.29 RCE → billing-srv-01 (GAP-003)
- IoT: BD Alaris known CVE → infusion pumps (GAP-001)

## Supply Chain Compromise
- EHR/PACS/Backup/Billing/AD: MedTech access → flat net → whole server tier (T5)
- IoT: Siemens → WS-RAD-01 → flat net → IoT segment (10.10.3.0/24 not VLAN-separated)
## Insider (Malicious)
- EHR: out-of-scope record access (T3 Sc.4 pattern)
- PACS: shared login misuse, no attribution (GAP-008)
- Backup: sabotage before termination (T1 Report D pattern)
- Network Core: unlocked closet, no camera → physical tamper (GAP-005)
- AD: ghost VPN account retained post-termination (T3 Sc.2)

## Insider (Negligent)
- PACS: shared login, negligent daily use (GAP-008)
- AD: plaintext admin creds emailed (T3 Sc.5)

## Physical Access
- EHR/Backup/Billing/AD: server room generic badge, no camera → direct hardware access
- PACS: workstation left logged in (shared login)
- Network Core: unlocked closet, creds posted on wall (GAP-005)
- IoT: physical access to ICU/ER devices → tampering

## Most Connected Assets (top 3)
- PACS (7/7 vectors) — shared/unattributed login + flat network = every vector reaches it
- EHR (6/7) — core clinical data draws every actor; open PostgreSQL skips the app tier entirely
- Active Directory (6/7) — highest-value pivot, nearly every vector routes toward it

## Most Versatile Vectors (top 3)
- Physical Access (7/7 assets) — weak server room badge + unlocked closet reach everything
- VPN Exploit (6/7) — single external entry point drops attacker straight onto the flat network
- Supply Chain Compromise (6/7) — vendor access already sits inside the flat network
