# Task 18 — The Data Classification Matrix

MedDefense Health Systems — 1x04 Task 18

## Part 1 — Data Type Inventory

| Data Type | MedDefense Examples |
|---|---|
| Regulated (HIPAA/PHI) | Patient records (EHR), diagnoses, DICOM images, prescriptions |
| PII | Patient names/SSNs/DOB/addresses; employee personal data (overlaps with Regulated for patients) |
| Financial | Billing records, credit card numbers, insurance information (overlaps with PII) |
| Intellectual Property | No significant IP identified for MedDefense as a hospital operator; would apply if research/proprietary protocols exist |
| Legal | Vendor contracts, compliance documentation, incident/breach reports |
| Operational | Staff directory, meeting schedules, IT asset inventory, network diagrams |

## Part 2 — Classification Levels

| Level | Who Can Access | Encryption Required | If Exposed |
|---|---|---|---|
| Public | Anyone (public website content) | None required at rest; TLS in transit | No meaningful harm — hospital address, visiting hours |
| Internal | Authenticated employees only | Standard full-disk/volume encryption at rest; TLS in transit | Minor reputational/privacy concern, low regulatory risk |
| Confidential | Named roles (finance, leadership, IT security) | Database/file-level AES-256 at rest; TLS 1.2+ in transit | Financial/competitive harm, contract breach, moderate legal exposure |
| Restricted | Strict need-to-know, role-based + MFA (clinicians for PHI, DBAs for encrypted DB, security team for keys) | Database/record-level AES-256-GCM, HSM/KMS key management (T14); TLS 1.3 preferred | HIPAA breach, regulatory fines, patient harm, reputational damage, legal liability |

## Part 3 — The Classification Decision Tree

Is it patient data?
  -> Yes: RESTRICTED
  -> No: Does it contain credentials or encryption keys?
       -> Yes: RESTRICTED
       -> No: Does it contain financial information (billing, card numbers)?
            -> Yes: CONFIDENTIAL
            -> No: Is it legal/contractual (vendor agreements, compliance docs)?
                 -> Yes: CONFIDENTIAL
                 -> No: Is it internal operational data (schedules, staff directory)?
                      -> Yes: INTERNAL
                      -> No: Is it intended for public consumption (address, hours)?
                           -> Yes: PUBLIC
                           -> No / unclear: default to INTERNAL until formally classified

## Part 4 — Sovereignty and Geolocation

Data sovereignty matters for healthcare because PHI is subject to jurisdiction-specific laws, and breach-notification/regulatory authority can change based on where data physically resides. If the AWS region is a different state or country, HIPAA requires a BAA covering that region; a different country could add other regulations (e.g. GDPR). Encryption helps but doesn't fully solve it — a customer-managed key (T14) keeps MedDefense in control of confidentiality, but legal/contractual obligations tied to data location remain a governance issue, not just a technical one.


