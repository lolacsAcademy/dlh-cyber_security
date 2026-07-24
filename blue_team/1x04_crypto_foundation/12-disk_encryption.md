# Task 12 — The Disk Encryption Lab

MedDefense Health Systems — 1x04 Task 12

## Part 1 — LUKS Setup

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
→ 500 MiB file created

sudo cryptsetup luksFormat encrypted_volume.img
→ Confirmed overwrite, set passphrase, formatted successfully

sudo cryptsetup luksOpen encrypted_volume.img secure_vol
→ Opened, mapped to /dev/mapper/secure_vol

sudo mkfs.ext4 /dev/mapper/secure_vol
→ ext4 filesystem created, journal enabled

sudo mount /dev/mapper/secure_vol /mnt/secure_vol
echo "MedDefense LUKS test data - patient record placeholder" | sudo tee /mnt/secure_vol/testfile.txt
→ Test file written and confirmed readable

sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
→ Unmounted and closed successfully

## Part 2 — Verification

strings encrypted_volume.img | head -50
→ Pure binary noise, no readable trace of the test data. This proves encryption at rest works: raw access to the file (e.g. a stolen drive) yields nothing meaningful without the passphrase.

Reopen cycle:
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
cat /mnt/secure_vol/testfile.txt
→ "MedDefense LUKS test data - patient record placeholder" — data fully intact after close/reopen

sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
→ Closed successfully

## Part 3 — The LUKS Automation Script

See 12-luks_manager.sh. Supports create, open, close modes. Tested full cycle (create → open → write/read → close) successfully. Initial version had a bug: create only ran luksFormat without building a filesystem, causing open to fail with "wrong fs type, bad option, bad superblock." Fixed by having create also open the volume, run mkfs.ext4, then close it before finishing.

## Part 4 — MedDefense Backup Encryption Design

**Encryption level:** Volume-level (LUKS on the NAS's storage volume), not full-disk or file-level. Full-disk isn't practical on a NAS appliance handling multiple shares; file-level would require per-file key management overhead across every backup job. Volume-level protects everything written to that backup volume transparently, matching this lab's exact model.

**Performance overhead:** Based on T1 measurements (AES-256-CBC handled the 100MB test file without issue), LUKS's AES-XTS overhead is typically single-digit percentage CPU cost on modern hardware — acceptable for scheduled backup windows, though the NAS's specific CPU should be benchmarked before production rollout.

**Key storage:** NOT on the NAS itself — stored in a separate key management system (e.g. a dedicated KMS or an offline HSM), because if ransomware or an attacker compromises the NAS (as the kill chain scenario already demonstrated is possible), a key stored locally would be encrypted right alongside the data it's meant to protect, defeating the purpose entirely — this was literally Sarah Park's own concern noted in the Task 0 audit.

**If the key is lost:** All backups on that volume become permanently unrecoverable — this is the fundamental tradeoff of encryption at rest. Key backup/escrow (e.g. splitting the key or storing a secured copy with IT leadership) is mandatory before this goes into production, so a single lost key doesn't destroy MedDefense's entire backup history.

**Offsite/cloud replication:** Yes, the cloud replica must also be encrypted. It should use MedDefense's own key (customer-managed key), not the cloud provider's default key, so that even the cloud provider cannot read MedDefense's backups — keeping control of PHI entirely with MedDefense, consistent with HIPAA's expectations around data custody.
