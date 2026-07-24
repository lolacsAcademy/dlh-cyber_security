# Task 19 — The HIPAA Crypto Checkpoint

MedDefense Health Systems — 1x04 Task 19

## HIPAA Crypto Compliance Table

| HIPAA Requirement | Citation | Current MedDefense State | Compliant? | Gap / Remediation |
|---|---|---|---|---|
| Encryption and decryption of ePHI (addressable) | 45 CFR §164.312(a)(2)(iv) | EHR DB, billing DB, and PACS all unencrypted at rest (T0) | No | No encryption + no documented risk-based alternative. Remediate: AES-256-GCM at DB/volume level per T13, KMS/HSM key mgmt per T14 (T15 CRYPTO-001/004/006) |
| Transmission Security standard | 45 CFR §164.312(e)(1) | Patient portal still supports TLS 1.0 (Finding 005); DICOM traffic fully cleartext; DB connections permit non-SSL | No | Disable TLS 1.0/1.1 (T11), enable DICOM TLS (T15 CRYPTO-007), enforce hostssl-only (T15 CRYPTO-002/005) |
| Encryption of ePHI in transit (addressable) | 45 CFR §164.312(e)(2)(ii) | Same evidence as above — TLS 1.0 enabled, DICOM unencrypted, DB SSL not enforced | No | Same remediation as above; document risk analysis if any exception is retained |
| Person or Entity Authentication | 45 CFR §164.312(d) | AD authentication relies on NTHash (MD4); RC4/DES Kerberos encryption types enabled (Finding 018) | No | Disable RC4/DES Kerberos types, enforce AES-only tickets (T15 CRYPTO-008/009); this is a required standard, not addressable |

## Could MedDefense Pass a HIPAA Audit Today?

No. Every addressable encryption specification reviewed here is currently unmet, with no documented risk analysis showing a deliberate decision to use an equivalent alternative — which is what "addressable" actually requires. The single most critical deficiency an auditor would cite is the complete absence of encryption at rest for ePHI in the core patient database (ehr-db-01) — the hospital's actual clinical records sit entirely unencrypted on disk, exactly the scenario §164.312(a)(2)(iv) exists to prevent. This is compounded by Person/Entity Authentication (§164.312(d), a required standard) being undermined by broken Kerberos encryption types securing the credentials that control access to that same database.
