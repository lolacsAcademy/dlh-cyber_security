# Task 14 — Hardware Security and Key Management

MedDefense Health Systems — 1x04 Task 14

## Part 1 — Technology Comparison

| Technology | What It Is | What It Protects | Typical Cost | Typical Deployment |
|---|---|---|---|---|
| TPM | Chip on motherboard, TPM 2.0 standard | Boot integrity, disk encryption keys (BitLocker), device secrets | Effectively free — built in | Laptops, workstations, servers — one per device |
| HSM | Dedicated hardware/cloud appliance, FIPS 140-2 certified | High-value keys (signing, DB master keys, PKI root) | On-prem: tens of thousands upfront; cloud HSM-as-a-Service: ~$1-2/key/month | Centralized, shared across servers/apps |
| Secure Enclave | Isolated region within a CPU/SoC | App/data isolation on one device | Built into hardware already owned | Mobile devices, laptops, BYOD |
| KMS (Software) | Cloud provider key management service | Keys for cloud DBs, storage, services | ~$1/key/month plus fees | Cloud-native apps (AWS KMS, Azure Key Vault) |

## Part 2 — MedDefense Key Management Plan

| Asset | Key Storage | Access | Rotation | Compromised / Lost |
|---|---|---|---|---|
| Patient DB key (T13) | Cloud KMS/HSM, not the DB server | DBA role, via API | Annually or on suspicion | Revoke + re-encrypt / recover from HSM backup |
| Backup key (T12, NAS-01) | Separate KMS/HSM, off the NAS | IT security lead | Every 90 days | Revoke + re-encrypt / unrecoverable if lost, needs escrow |
| Portal TLS key (T10) | Server's protected key store | Sysadmin/DevOps | Every 200 days (T11 cycle) | Revoke cert (T9), reissue / reissue new pair |
| VPN tunnel keys | FortiGate device-local storage | Network admin | Every 90 days or on suspicion | Rotate both ends / regenerate, tunnel drops |

## Part 3 — The HSM Decision

Relevant risk (1x03 Risk Register, Scenario 2 — EHR breach): ALE ≈ $3,000,000/year. Directly applicable — patient DB is exactly the asset T13 recommends encrypting.

HSM cost: ~$1-2/key/month, ~4-5 keys currently = ~$60-120/year. Scaled to 20 keys = ~$240-480/year.

Comparison: a few hundred dollars/year vs. a $3,000,000/year ALE is not close. Even a small ARO reduction from HSM adoption far exceeds its cost.

Conclusion: investment clearly justified. Removes the single point of failure Sarah Park flagged in Task 0 (key stored alongside the data it protects).
