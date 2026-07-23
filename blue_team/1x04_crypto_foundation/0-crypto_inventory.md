# Data Protection Map — MedDefense Health Systems

W3-P1 Task 0 — Crypto Inventory

## 1. Patient medical records (EHR — PostgreSQL, ehr-db-01)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | None | ext4 filesystem, no encryption layer | Absent |
| In Transit | Partial (ssl=on) | pg_hba.conf allows non-SSL from 10.10.0.0/16 alongside SSL rules — cannot confirm which connections are encrypted | Weak |
| In Use | None | Decrypted in memory on ehr-srv-01; nurse workstations screensaver timeout set to "Never" | Absent |

## 2. Financial/billing data (MySQL, billing-srv-01)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | None | Unencrypted ext4; 1x00 crypto-miner incident confirmed DB files readable without MySQL credentials | Absent |
| In Transit | Not enforced | MySQL bound 0.0.0.0, SSL not enforced, plaintext protocol over flat network | Weak |
| In Use | — | Not addressed in audit notes | Not assessed |

## 3. Medical images (DICOM — PACS)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | None | Images unencrypted on local disk; headers partially plaintext | Absent |
| In Transit | None | DICOM ports 4242/11112 cleartext; DICOM TLS (PS3.15) supported but not configured | Absent |
| In Use | — | Not addressed in audit notes | Not assessed |

## 4. Credentials (Active Directory / app passwords)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | Mixed (NTHash/MD4 default; Kerberos AES-256/128 + RC4/DES enabled) | Finding 018 — RC4/DES still enabled | Weak |
| In Transit | None | LDAP unencrypted by default; LDAP signing not required — Finding 007 | Absent |
| In Use | — | Not addressed in audit notes | Not assessed |

## 5. Backup data (NAS-01)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | None | RAID-5, no encryption; Synology shared-folder AES-256-CBC feature exists but unused | Absent |
| In Transit | — | Notes cover DSM management exposure (Finding 015), not data-transfer encryption | Not assessed |
| In Use | N/A | Backup data has no meaningful "in use" state | N/A |

## 6. Email (O365)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | BitLocker + per-mailbox encryption (MS-managed keys) | Audit notes | Adequate |
| In Transit | TLS 1.2 enforced (Exchange Online, since 2023) | Audit notes | Adequate |
| In Use | None (no S/MIME or OME) | PHI sometimes emailed in plaintext despite policy | Absent |

## 7. VPN traffic (site-to-site tunnels)

| State | Protection | Evidence | Status |
|---|---|---|---|
| At Rest | N/A | Not a data-at-rest category | N/A |
| In Transit | AES-256/SHA-256, IKEv2 DH Group 14 (both tunnels) | FortiGate config; caveat — Westside endpoint is a consumer router (Netgear Nighthawk), firmware history unknown | Adequate* |
| In Use | N/A | Not applicable | N/A |

## Gap Summary

- Total matrix cells: 21
- N/A (not applicable to data type): 3
- Not assessed (audit notes silent): 4
- Assessed cells: 14
  - Adequate: 3 — Email at rest, Email in transit, VPN in transit
  - Weak: 3 — EHR in transit, Billing in transit, Credentials at rest
  - Absent: 8 — EHR at rest, EHR in use, Billing at rest, PACS at rest, PACS in transit, Credentials in transit, Backup at rest, Email in use

Crypto coverage: 3/21 = 14.3% of all cells adequate; 3/14 = 21.4% of assessed cells adequate (7 cells lack evidence or do not apply).
