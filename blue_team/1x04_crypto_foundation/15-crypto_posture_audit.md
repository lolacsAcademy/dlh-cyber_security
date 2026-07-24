# Task 15 — The Crypto Posture Audit

MedDefense Health Systems — 1x04 Task 15

## Crypto Findings

**CRYPTO-001**
Data Category: Patient medical records (EHR, ehr-db-01)
Data State: At rest
Current Protection: None
Vulnerability Reference: N/A (T0 audit notes)
Risk Reference: 1x03 Scenario 2 — EHR breach, ALE ≈ $3,000,000/year
Algorithm Assessment: Absent — no algorithm in use
Recommended Protection: AES-256-GCM
Encryption Level: Database-level TDE (T13)
Key Management: Cloud KMS/HSM, DBA-only access (T14)
Implementation Priority: Immediate

**CRYPTO-002**
Data Category: Patient medical records (EHR, ehr-db-01)
Data State: In transit
Current Protection: Partial (ssl=on, non-SSL permitted)
Vulnerability Reference: N/A (T0 audit notes)
Risk Reference: 1x03 Scenario 2 — EHR breach, ALE ≈ $3,000,000/year
Algorithm Assessment: Weak — SSL not enforced consistently
Recommended Protection: TLS 1.2/1.3 enforced, hostssl-only
Encryption Level: N/A (transport)
Key Management: N/A
Implementation Priority: Phase 1

**CRYPTO-003**
Data Category: Patient medical records (EHR, ehr-db-01)
Data State: In use
Current Protection: None
Vulnerability Reference: N/A (T0 audit notes)
Risk Reference: 1x03 Scenario 2 — EHR breach, ALE ≈ $3,000,000/year
Algorithm Assessment: Absent — no protection while processed/displayed
Recommended Protection: Session timeout + screen lock policy (compensating control)
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 2

**CRYPTO-004**
Data Category: Financial/billing data (MySQL, billing-srv-01)
Data State: At rest
Current Protection: None
Vulnerability Reference: 1x00 crypto-miner incident
Risk Reference: 1x03 Scenario 1 — billing ransomware, ALE ≈ $142,000/year
Algorithm Assessment: Absent — no algorithm in use
Recommended Protection: AES-256-GCM
Encryption Level: Database-level TDE + Record-level tokenization on card numbers (T13, T7)
Key Management: Cloud KMS/HSM, DBA-only access (T14)
Implementation Priority: Immediate

**CRYPTO-005**
Data Category: Financial/billing data (MySQL, billing-srv-01)
Data State: In transit
Current Protection: Not enforced
Vulnerability Reference: N/A
Risk Reference: 1x03 Scenario 1 — billing ransomware, ALE ≈ $142,000/year
Algorithm Assessment: Weak — SSL available but not enforced
Recommended Protection: TLS 1.2/1.3 enforced on MySQL connections
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 1

**CRYPTO-006**
Data Category: Medical images (DICOM, PACS-srv-01)
Data State: At rest
Current Protection: None
Vulnerability Reference: N/A
Risk Reference: Not separately quantified in 1x03 risk register
Algorithm Assessment: Absent — no algorithm in use
Recommended Protection: AES-256-GCM
Encryption Level: Volume-level (T13)
Key Management: Cloud KMS/HSM (T14)
Implementation Priority: Phase 1

**CRYPTO-007**
Data Category: Medical images (DICOM, PACS-srv-01)
Data State: In transit
Current Protection: None
Vulnerability Reference: N/A
Risk Reference: Not separately quantified in 1x03 risk register
Algorithm Assessment: Absent — DICOM TLS supported but not configured
Recommended Protection: DICOM TLS (PS3.15) on ports 4242/11112
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 1

**CRYPTO-008**
Data Category: Credentials (Active Directory)
Data State: At rest
Current Protection: Mixed — NTHash/MD4 default, RC4/DES Kerberos still enabled
Vulnerability Reference: Finding 018 (1x02)
Risk Reference: 1x03 Scenario 5 — VPN/flat network, ALE ≈ $2,864,000/year
Algorithm Assessment: Broken (MD4/RC4/DES) — per T6
Recommended Protection: Disable RC4/DES Kerberos types, enforce AES256-CTS-HMAC-SHA1-96
Encryption Level: N/A (directory service)
Key Management: N/A (managed via AD)
Implementation Priority: Immediate

**CRYPTO-009**
Data Category: Credentials (LDAP)
Data State: In transit
Current Protection: None — unencrypted, signing not required
Vulnerability Reference: Finding 007 (1x02)
Risk Reference: 1x03 Scenario 5 — VPN/flat network, ALE ≈ $2,864,000/year
Algorithm Assessment: Absent — per T6, known weak point
Recommended Protection: Enforce LDAPS / require LDAP signing
Encryption Level: N/A (directory service)
Key Management: N/A
Implementation Priority: Immediate

**CRYPTO-010**
Data Category: Backup data (NAS-01)
Data State: At rest
Current Protection: None
Vulnerability Reference: Finding 015 (1x02, related DSM exposure)
Risk Reference: 1x03 Scenario 5 — VPN/flat network, ALE ≈ $2,864,000/year
Algorithm Assessment: Absent — no algorithm in use
Recommended Protection: AES-256 via LUKS (T12 design)
Encryption Level: Volume-level (T13, T12)
Key Management: Separate KMS/HSM, off the NAS, IT security lead only (T14)
Implementation Priority: Immediate

**CRYPTO-011**
Data Category: Email data (O365)
Data State: In use
Current Protection: None — no S/MIME/OME, PHI sometimes sent in plaintext
Vulnerability Reference: N/A
Risk Reference: Not separately quantified in 1x03 risk register
Algorithm Assessment: Absent — message-level encryption not configured
Recommended Protection: S/MIME or Microsoft OME for PHI-containing messages
Encryption Level: Record-level, message-scoped (T13)
Key Management: N/A (Microsoft-managed for mailbox at rest)
Implementation Priority: Phase 2

## Posture Score

11 of 11 identified Weak/Absent cells from T0 now have a documented remediation path — 100% of identified gaps addressed.

Against the full 21-cell T0 matrix: 3 cells already Adequate, 11 now covered, 7 remain Not Assessed/N/A (no T0 evidence available). 14 of 21 cells (66.7%) have a clear, evidence-based status.

## Top 3 Crypto Risks (ranked)

1. CRYPTO-001 (EHR database, at rest) — largest quantified risk, 1x03 Scenario 2, ALE ≈ $3,000,000/year. Core patient DB unprotected at rest.
2. CRYPTO-008 / CRYPTO-009 (Credentials, AD/LDAP) — 1x03 Scenario 5, ALE ≈ $2,864,000/year. Broken Kerberos + unencrypted LDAP enable full-network access given the flat network (GAP-011).
3. CRYPTO-004 (Billing database, at rest) — 1x03 Scenario 1, ALE ≈ $142,000/year. Already exploited once: the 1x00 crypto-miner incident showed billing DB files directly readable without credentials.
