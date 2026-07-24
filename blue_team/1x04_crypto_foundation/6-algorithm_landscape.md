# 6-algorithm_landscape: The Algorithm Landscape

MedDefense Health Systems — 1x04 Task 6

## Algorithm Reference Table

| Algorithm | Type | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|---|---|---|---|---|---|---|
| AES-128 | Symmetric | 128-bit | General-purpose encryption | Current | — | Constrained devices where AES-256 overhead matters |
| AES-192 | Symmetric | 192-bit | General-purpose encryption | Current | — | Not currently used; no specific requirement |
| AES-256 | Symmetric | 256-bit | Bulk data encryption at rest/in transit | Current | — | Recommended standard for DB, backup, portal (Sarah Park's target) |
| DES | Symmetric | 56-bit | Legacy block cipher | Broken | 56-bit keyspace trivially brute-forced | Still enabled for Kerberos tickets (Finding 018) — must disable |
| 3DES | Symmetric | 112-bit effective | Legacy transitional cipher | Deprecated (NIST 2023) | Sweet32 birthday attack on 64-bit blocks | Not confirmed in use; exclude from cipher configs |
| ChaCha20-Poly1305 | Symmetric AEAD | 256-bit | AEAD for low-power/mobile devices | Current | — | Good AES-GCM alternative for BD Alaris pumps / Philips monitors |
| RC4 | Symmetric | 40-2048 (typ. 128) | Legacy stream cipher | Broken | Statistical keystream biases allow plaintext recovery | Still enabled for Kerberos tickets (Finding 018) — must disable |
| Blowfish | Symmetric | 32-448-bit | Legacy block cipher (used inside bcrypt) | Deprecated | 64-bit block size vulnerable to birthday attacks on large data | Not used directly; only present inside bcrypt KDF |
| RSA-2048 | Asymmetric | 2048-bit | Key exchange / digital signatures | Current (minimum) | — | T2/T5 key pairs, patient portal TLS cert |
| RSA-4096 | Asymmetric | 4096-bit | Key exchange / signatures, longer lifetime | Current | — | Recommended for CA/root certificates |
| ECC P-256 | Asymmetric | 256-bit | TLS key exchange/signatures, constrained devices | Current | — | Recommended for BD Alaris / Philips monitor TLS |
| ECC P-384 | Asymmetric | 384-bit | Higher-security TLS/signatures | Current | — | Recommended for backend server certs |
| Diffie-Hellman | Asymmetric | 2048-bit (typ. modulus) | Key exchange | Current, needs authentication | — | Used in Central-Westside/HQ VPN tunnels (T4) — needs cert-based auth |
| ECDHE | Asymmetric | 256/384-bit | Ephemeral key exchange, forward secrecy | Current | — | Recommended for patient portal TLS 1.3 migration |
| MD5 | Hash | 128-bit | Legacy checksums | Broken | Collision attacks demonstrated | Underlies NTHash / AD credential storage (Finding 018) — must replace |
| SHA-1 | Hash | 160-bit | Legacy signatures/certs | Deprecated/Broken | Collision attacks (SHAttered, 2017) | Not confirmed in use; exclude from cert signing |
| SHA-256 | Hash | 256-bit | General-purpose hashing/integrity | Current | — | Used throughout (T3, T5 signatures) |
| SHA-512 | Hash | 512-bit | High-security hashing | Current | — | Alternative for long-term integrity verification |
| SHA-3 | Hash | 256/512-bit (Keccak) | Modern hash standard | Current | — | Not yet adopted; future-proofing option |
| PBKDF2 | KDF | Variable iterations | Password-based key derivation | Current, weaker than memory-hard KDFs | — | Not confirmed in use for app passwords |
| bcrypt | KDF | Cost-factor based | Password hashing | Current | — | Candidate for app password storage |
| Argon2 | KDF | Memory + cost factor | Password hashing | Current (recommended) | — | Recommended per T3 for application password storage |
| scrypt | KDF | Memory/parallelization params | Password hashing | Current | — | Alternative to Argon2; not currently used |

## MedDefense Crypto Gap Analysis

1. RC4 enabled for Kerberos ticket encryption (Finding 018) — broken stream cipher, statistically recoverable. Replacement: disable RC4 encryption types on all domain controllers; enforce AES256-CTS-HMAC-SHA1-96 only.

2. DES enabled for Kerberos ticket encryption (Finding 018) — 56-bit key trivially brute-forced. Replacement: disable DES encryption types entirely; no legitimate reason for it to remain enabled.

3. MD5-based NTHash used for AD credential storage — MD4/MD5-family hash, unsalted, cryptographically broken. Replacement: cannot be changed within NTLM itself, but MedDefense should move authentication to Kerberos-only (disable NTLM fallback) and implement Argon2 for any custom application password stores outside AD.

4. TLS 1.0 supported on the patient portal (Finding 005) — vulnerable to BEAST, POODLE, Lucky Thirteen. Replacement: disable TLS 1.0/1.1, enable TLS 1.3 with ECDHE cipher suites, configure HSTS and OCSP stapling.
