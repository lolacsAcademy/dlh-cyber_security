# Task 4 — The Crypto Emergency

## Part 1: Crypto Attack Surface Mapping

**Phase 3 — Lateral Movement**
Crypto Weakness: CRYPTO-008 — AD Kerberos, RC4/DES still enabled
What Crimson Tide Exploits: Kerberoasting cracks RC4-encrypted service tickets offline for domain-level credentials
Recommended Crypto Fix: Disable RC4/DES, enforce AES256-CTS-HMAC-SHA1-96
Emergency Timeline: No — needs a maintenance window (auth-breaking risk), already Tier 3 in Task 3

**Phase 4 — Data Exfiltration**
Crypto Weakness: CRYPTO-001 (EHR DB) / CRYPTO-004 (billing DB) — no encryption at rest
What Crimson Tide Exploits: Copies raw DB files directly from disk, no credentials needed
Recommended Crypto Fix: AES-256-GCM, database-level TDE; billing DB adds tokenization
Emergency Timeline: Partially — full TDE rollout needs testing, but KMS/HSM key separation can start within 72h

**Phase 5 — Backup Destruction**
Crypto Weakness: CRYPTO-010 — NAS-01 backup, no encryption at rest
What Crimson Tide Exploits: Attacker verifies backup value before destroying it (3 of 5 real incidents)
Recommended Crypto Fix: AES-256 via LUKS (T12 design), key stored off-NAS
Emergency Timeline: Yes — can layer onto the already-isolated NAS-01 within 72h
## Part 2: Encryption Priority Re-ranking

Original T13 Immediate tier (5 items, by CRYPTO-ID order): CRYPTO-001, CRYPTO-004, CRYPTO-008, CRYPTO-009, CRYPTO-010.

**Updated order for Crimson Tide:**
1. **CRYPTO-001** (EHR DB at rest) — unchanged at #1: highest ALE ($3M/yr) and the exact mechanism the advisory describes for Phase 4.
2. **CRYPTO-010** (Backup at rest) — moved up from #5. Directly counters the advisory's Phase 5 tactic (verify-then-destroy), and NAS-01 is already physically isolated tonight (Task 3), making this the fastest win to layer encryption onto.
3. **CRYPTO-004** (Billing DB at rest) — unchanged relative position: same mechanism as CRYPTO-001, lower ALE.
4. **CRYPTO-008** (Kerberos RC4/DES) — moved down from #3. Still directly named in the advisory (Kerberoasting), but requires a maintenance window and carries outage risk — can't be safely rushed into 72 hours, so it stays technically urgent but operationally behind the encryption-at-rest fixes.
5. **CRYPTO-009** (LDAP encryption) — unchanged at #5: not specifically named in this advisory.
## Part 3: The "What If" Calculation

If ehr-db-01 had been encrypted at rest per CRYPTO-001, Phase 4 wouldn't proceed as described — no more copying raw files off the filesystem, since TDE makes them ciphertext without the key.

But the stated condition — domain admin access, key stored on the same server — is a misconfiguration against T14's design (key belongs in a separate KMS/HSM, DBA-only). Under that misconfiguration, the data is still exfiltrable: domain admin generally extends to local admin, enough to read the key file alongside the encrypted database and decrypt it offline.

Even under the correct T14 design, the same attacker profile isn't fully blocked: TDE protects raw files at rest, not a live authenticated session. Domain admin can typically reach the database engine directly, and the engine decrypts transparently for any authorized query. So encryption at rest closes the "just copy the files" path Crimson Tide used, but not exfiltration via admin-level database access — that needs separate controls (DB access scoped apart from domain admin, anomaly detection on large data pulls), neither of which is a crypto fix.
