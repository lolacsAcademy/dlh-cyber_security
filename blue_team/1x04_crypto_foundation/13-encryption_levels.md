# Task 13 — The Encryption Levels

MedDefense Health Systems — 1x04 Task 13

## Encryption Level Comparison

| Level | Scope | Performance Impact | Key Management | Use Case |
|---|---|---|---|---|
| Full-disk | Entire physical/virtual disk | Low, transparent with AES-NI | One key, tied to boot (TPM/passphrase) | Best when a whole device could be lost/stolen (laptop) |
| Partition | One logical partition | Low, similar to full-disk | Per-partition key | Best when only some partitions need protection |
| Volume | Logical volume, may span disks | Low-moderate, transparent once mounted | Per-volume key | Best for server/NAS storage (matches T12 LUKS lab) |
| File | Individual files | Overhead per file open/close | Per-file/per-directory keys | Best for protecting specific files without encrypting everything |
| Database | Entire DB or tablespace (TDE) | Moderate, transparent to queries | DB engine manages master + data keys | Best for protecting a whole DB with no app changes |
| Record | Individual fields/records | Highest — per-field encrypt/decrypt, breaks indexing | Most complex — per-field/record keys | Best for a few extremely sensitive fields (SSN, card numbers) |

## MedDefense Encryption Level Map

**Patient records (PostgreSQL, ehr-db-01):** Database-level (TDE), plus Record-level on SSN. Whole DB holds PHI (T0); TDE covers it transparently; record-level adds SSN access control (matches T7 masking).

**Backup data (NAS-01):** Volume-level, per the T12 LUKS design already specified.

**Financial records (MySQL, billing-srv-01):** Database-level (TDE), plus Record-level tokenization on card numbers (matches T7 design). DB was fully unencrypted (T0); tokenization keeps card numbers out of the DB entirely.

**Medical images (PACS, pacs-srv-01):** Volume-level. PACS storage was fully unencrypted (T0). Volume-level protects every image without per-file key overhead.

**Email data (O365):** Record-level (S/MIME or OME) for PHI-containing messages. Mailbox is already protected at rest by Microsoft (T0), but message-level encryption is missing and staff sometimes email PHI in plaintext.

**Employee laptops:** Full-disk encryption. Classic use case — lost/stolen laptop reveals nothing, minimal staff friction.

**BD Alaris pump firmware/configuration:** File-level, on firmware/config files specifically. Constrained embedded device (T6 favored ECC for this reason) — full-disk isn't practical; file-level protects just the sensitive artifacts.
