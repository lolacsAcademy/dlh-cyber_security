# Task 20 — The Implementation Playbook

MedDefense Health Systems — 1x04 Task 20

The 5 highest-priority changes, all rated Immediate in the T15 Crypto Posture Audit.

## Action #1: Encrypt EHR Database at Rest
Priority: Immediate
System Affected: ehr-db-01
Prerequisites: KMS/HSM key management in place (T14); maintenance window scheduled; full backup of ehr-db-01 taken and verified; TDE-compatible PostgreSQL version confirmed

Steps:
  1. Provision encryption key in KMS/HSM
  2. Enable PostgreSQL tablespace/TDE encryption with the provisioned key
  3. Migrate existing data to the encrypted tablespace
  4. Update application connection config if needed
  5. Confirm EHR application functions normally against the encrypted DB

Validation:
  - Query tablespace/encryption status to confirm encryption is active
  - Confirm application read/write operations succeed with no errors
  - Confirm no performance degradation beyond acceptable threshold

Rollback:
  - Restore from the pre-encryption backup if data corruption or performance failure occurs
  - Maximum acceptable downtime: 2 hours (clinical system)

Maintenance Window: Overnight required — EHR is used by clinical staff continuously
Communication: Notify James Chen, Sarah Park, and clinical staff via IT bulletin 48 hours in advance; confirm all-clear after validation

## Action #2: Encrypt Billing Database at Rest
Priority: Immediate
System Affected: billing-srv-01
Prerequisites: KMS/HSM key provisioned; full backup taken and verified; maintenance window scheduled

Steps:
  1. Provision encryption key in KMS/HSM
  2. Enable MySQL InnoDB tablespace encryption with the provisioned key
  3. Re-encrypt existing billing data
  4. Update application connection config if needed
  5. Confirm billing application functions normally

Validation:
  - Confirm InnoDB tablespace encryption status via information_schema
  - Confirm billing transactions process successfully
  - Confirm no performance degradation beyond acceptable threshold

Rollback:
  - Restore from the pre-encryption backup if failure occurs
  - Maximum acceptable downtime: 4 hours

Maintenance Window: Business hours OK, low-traffic period preferred (early morning)
Communication: Notify Robert Kim (CFO), billing department, and Sarah Park before and after

## Action #3: Disable RC4/DES Kerberos Encryption Types
Priority: Immediate
System Affected: ad-dc-01, ad-dc-02
Prerequisites: Inventory of systems/service accounts currently using RC4/DES confirmed (avoid breaking legacy dependencies); change approved by IT leadership

Steps:
  1. Audit current Kerberos encryption types in use (msDS-SupportedEncryptionTypes)
  2. Update Group Policy to enforce AES256-CTS-HMAC-SHA1-96 / AES128 only
  3. Disable RC4/DES support on both domain controllers
  4. Force Kerberos ticket renewal across affected accounts
  5. Monitor authentication logs for failures

Validation:
  - Confirm no RC4/DES tickets are issued (event logs)
  - Confirm all critical service accounts authenticate successfully post-change

Rollback:
  - Re-enable RC4 temporarily via Group Policy if a critical legacy system fails to authenticate
  - Maximum acceptable downtime: 1 hour (authentication is foundational)

Maintenance Window: Overnight required — affects all domain authentication
Communication: Notify all IT staff, department heads (potential lockout risk), James Chen, and Sarah Park before and after

## Action #4: Enforce LDAPS / Require LDAP Signing
Priority: Immediate
System Affected: ad-dc-01, ad-dc-02
Prerequisites: LDAPS certificate issued and installed on both DCs; inventory of applications using LDAP bind confirmed

Steps:
  1. Install the LDAPS certificate on both domain controllers
  2. Enable "Require LDAP Server Signing" via Group Policy
  3. Redirect application LDAP bind configs to LDAPS (port 636) where applicable
  4. Test LDAP signing enforcement
  5. Monitor for bind failures

Validation:
  - Confirm LDAPS connections succeed
  - Confirm no unsigned LDAP binds succeed post-change
  - Confirm all applications relying on LDAP continue functioning

Rollback:
  - Revert the Group Policy signing requirement if a critical application breaks
  - Maximum acceptable downtime: 1 hour

Maintenance Window: Overnight required
Communication: Notify IT staff, application owners dependent on LDAP, and James Chen before and after

## Action #5: Encrypt Backup Volume on NAS-01
Priority: Immediate
System Affected: NAS-01
Prerequisites: KMS/HSM key provisioned off-NAS (T14); current backup set verified/exported elsewhere as a safety net; maintenance window scheduled

Steps:
  1. Provision a LUKS-compatible encryption key in KMS/HSM (per T12/T14 design)
  2. Create a new encrypted volume on NAS-01 with the key stored off-NAS
  3. Migrate existing backup data to the new encrypted volume
  4. Update backup jobs to target the new encrypted volume
  5. Decommission the old unencrypted volume

Validation:
  - Confirm backup jobs complete successfully to the encrypted volume
  - Confirm raw volume inspection shows no readable plaintext (per T12 strings test)
  - Confirm a restore test from the encrypted volume succeeds

Rollback:
  - Redirect backup jobs back to the old unencrypted volume if migration fails (keep it until validation is complete)
  - Maximum acceptable downtime: 8 hours

Maintenance Window: Overnight required
Communication: Notify Sarah Park and the IT security lead before and after; confirm backup validation complete before decommissioning the old volume
