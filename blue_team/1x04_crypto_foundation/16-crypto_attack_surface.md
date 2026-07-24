# Task 16 — The Cryptographic Attack Surface

MedDefense Health Systems — 1x04 Task 16

## Attack: TLS Downgrade
Mechanism: Attacker on-path manipulates the handshake so client/server negotiate down to the weakest mutually supported protocol.
MedDefense Vulnerability: Patient portal supports TLS 1.0 alongside TLS 1.2.
Evidence: Finding 005 (1x02)
Viable Today: Yes — TLS 1.0 still enabled, not yet remediated.
Mitigation: Disable TLS 1.0/1.1 entirely, per T11 hardened config (TLS 1.2/1.3 only).

## Attack: Collision Attack (MD5 in Kerberos)
Mechanism: Attacker finds two inputs producing the same MD5/MD4 hash, undermining its integrity guarantee.
MedDefense Vulnerability: AD's NTHash is MD4-based; RC4 Kerberos types (MD4/MD5-derived keys) still enabled.
Evidence: Finding 018 (1x02); T3 Part 2
Viable Today: Yes — RC4/DES enabled, MD4-based NTHash unavoidable within NTLM.
Mitigation: Disable RC4/DES Kerberos types, migrate to AES-only tickets (T6, T15 CRYPTO-008).

## Attack: Birthday Attack (theoretical)
Mechanism: Exploits the birthday paradox — finding any two colliding inputs takes ~sqrt of the output space, not the full space (~2^64 for MD5 vs ~2^128 for SHA-256).
MedDefense Vulnerability: Relevant wherever MD5/MD4-family hashes remain — Kerberos/NTHash internals.
Evidence: T3 Part 2 (birthday math); T6 (MD5 status: Broken)
Viable Today: Partially — relevant for MD5/MD4 already in production; SHA-256 use elsewhere (T3, T5) remains safe.
Mitigation: Ensure no remaining MD5/SHA-1 usage anywhere; standardize on SHA-256+ per T6.

## Attack: Kerberoasting
Mechanism: Attacker requests RC4-encrypted service tickets, extracts them, cracks offline via the weak NTHash-derived key.
MedDefense Vulnerability: RC4 enabled for Kerberos service ticket encryption.
Evidence: Finding 018 (1x02); T3, T6, T15 CRYPTO-008
Viable Today: Yes — RC4 confirmed enabled, no remediation applied.
Mitigation: Disable RC4 Kerberos encryption type, enforce AES-only tickets (T15 CRYPTO-008).

## Attack: On-path/MITM on Unencrypted Channels
Mechanism: Attacker on the network reads or modifies traffic with no encryption at all.
MedDefense Vulnerability: DICOM traffic (PACS) fully unencrypted; EHR/billing DB connections permit non-SSL.
Evidence: T0 (PACS In Transit: Absent; EHR/Billing In Transit: Weak); Finding 007 (LDAP, related pattern)
Viable Today: Yes — confirmed unencrypted in T0 audit.
Mitigation: Enable DICOM TLS (PS3.15), enforce hostssl-only in pg_hba.conf, require TLS for MySQL (T15 CRYPTO-002/005/006/007).

## Attack: Key Recovery from Memory
Mechanism: With root access, an attacker can dump process memory and find key material, since keys must be plaintext in RAM to be usable.
MedDefense Vulnerability: billing-srv-01 already had a confirmed root-level compromise (1x00 crypto-miner incident); a locally-loaded AES key would be recoverable the same way.
Evidence: 1x00 crypto-miner incident; T14 key management design
Viable Today: Conditionally — mitigated for keys following T14 (KMS/HSM keeps the master key off the app server), but any legacy local key file would remain exposed to root.
Mitigation: Strictly follow the T14 key management plan (keys never stored on the server they encrypt), combined with least-privilege root access.
