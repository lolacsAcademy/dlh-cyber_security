# 7-obfuscation_toolkit: The Obfuscation Toolkit

MedDefense Health Systems — 1x04 Task 7

## Part 1 — Technique Comparison

| Technique | What It Does | Recoverable? By Whom | Healthcare Use Case |
|---|---|---|---|
| Encryption | Transforms data into ciphertext using a reversible algorithm and key | Yes — by anyone holding the correct decryption key | Encrypting the EHR database at rest so a stolen disk yields no readable patient data |
| Hashing | One-way transform into a fixed-size digest; not designed to be reversed | No — not intended to be reversible; only re-computed and compared | Storing password hashes so even MedDefense IT cannot see a user's actual password |
| Tokenization | Replaces sensitive data with a non-sensitive substitute (token) that has no mathematical relationship to the original | Yes — but only by looking up the original in a separate secure vault, not by computation | Replacing patient credit card numbers with tokens in the billing system |
| Data Masking | Partially or fully hides parts of a value while preserving its format for display | Partially — masked portion is not recoverable from the masked value itself; full value stays in the source system for authorized users | Showing clinicians XXX-XX-4321 instead of a full SSN on a chart screen |
| Steganography | Hides data within other, unrelated data (e.g. an image file) so its presence is not obvious | Yes — by anyone who knows the hiding method/key and extracts it | Legitimate use: watermarking DICOM images to prove authenticity; illegitimate use: hiding exfiltrated data inside image files |

## Part 2 — MedDefense Tokenization Design

**What is tokenized:** Full credit card numbers (PAN) collected during billing. The token takes a format-preserving form — same length and structure as a card number (e.g. 16 digits), but mathematically unrelated to the original, so downstream billing systems that expect a card-number-shaped field continue to work without modification.

**Where the vault lives and how it's protected:** The token-to-PAN mapping lives in a dedicated token vault, isolated on its own hardened server segment, separate from the general billing database and from the flat network the billing app currently sits on. The vault itself is encrypted at rest with AES-256, access is restricted to a small number of named service accounts (not general billing staff), and every lookup is logged. Access control uses least privilege: the billing application can request tokenization/detokenization via an API, but no human account has direct database access to the vault.

**If the vault is compromised:** An attacker who compromises the token vault gains access to real card numbers — this is the single point of failure of tokenization, which is why the vault must be MedDefense's most tightly controlled asset. Outside the vault, stolen tokens from the billing database are useless on their own, since they cannot be reversed without vault access.

**Tokenization vs. encrypting the card numbers directly:** Tokenization advantage: the billing database itself never contains recoverable card data, so a breach of that database (which is far more exposed than a dedicated vault) yields nothing usable, and it can reduce PCI-DSS compliance scope for systems that only handle tokens. Tokenization disadvantage: it introduces a new single point of failure (the vault) and requires a lookup call for every detokenization, versus decryption which can happen locally with a key. Encryption's advantage is simplicity — no separate vault system to build and protect — but its disadvantage is that every system holding the ciphertext and the key can, in principle, recover the real card number, widening the exposure surface compared to tokenization.

## Part 3 — Data Masking Examples

| Data Field | Full Value | Nurse (Clinical) | Billing Clerk | Reception |
|---|---|---|---|---|
| SSN | 987-65-4321 | XXX-XX-4321 — enough to confirm identity, full SSN not needed for clinical care | 987-65-4321 (full) — required for insurance claim submission | Not displayed — reception only needs other identifiers (name, DOB) to check patients in |
| Patient Name | Maria Gonzalez | Maria Gonzalez (full) — required to correctly identify the patient during care | Maria Gonzalez (full) — required for invoicing and insurance correspondence | Maria Gonzalez (full) — required to greet and check in the correct patient |
| Diagnosis | Type 2 Diabetes | Type 2 Diabetes (full) — required for clinical decision-making | E11 (ICD-10 billing code only) — billing needs the code for claims, not clinical detail | Not visible — reception has no clinical need-to-know for diagnosis information |

## Part 4 — Steganography as Threat Vector

Steganography is a serious DLP concern for MedDefense because DICOM medical images are large binary files (often tens of megabytes) that are routinely and legitimately transferred between facilities, radiologists, and referring physicians, so large outbound image traffic never looks unusual on its own. A malicious insider could embed exfiltrated patient records — SSNs, billing data, other EHR content — inside the unused bits of a DICOM image's pixel data or metadata, then send that file through a channel already approved for imaging transfers (email, PACS replication, USB transport to another facility). This is harder to detect than traditional exfiltration because the file's size, type, and destination all appear completely normal — DLP tools that only flag known-sensitive file types (spreadsheets, database dumps) or scan for plaintext patterns like SSN formats will not inspect inside an image's binary payload. The DLP control from the 1x03 security strategy would help here: content-aware DLP with deep file inspection, plus anomaly-based monitoring of outbound file sizes and destinations for imaging traffic, could flag DICOM files that are unusually large for their study type or that are sent to unexpected external destinations.
