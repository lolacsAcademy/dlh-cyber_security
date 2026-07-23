# 2-asymmetric_analysis: The Asymmetric Engine

MedDefense Health Systems — 1x04 Task 2

## Part 1 — RSA Key Generation and Encryption

openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem -in patient_test.txt -out rsa_encrypted.bin
openssl pkeyutl -decrypt -inkey rsa_private.pem -in rsa_encrypted.bin -out rsa_decrypted.txt

Verified with diff patient_test.txt rsa_decrypted.txt — no differences, decryption exact.

Attempt on 100MB testfile:

openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem -in testfile -out rsa_large_test.bin

Error: data too large for key size (rsa_pk1.c:132)

RSA-2048 with PKCS1 padding can only encrypt messages up to roughly 245 bytes (key size minus padding overhead) in a single operation, since the ciphertext block cannot exceed the modulus size. This is a mathematical property of the algorithm, not a configuration limit. In practice this means RSA is never used to encrypt bulk data directly — it is used only to encrypt small payloads, typically a symmetric session key, which is why the hybrid model (Part 3) exists.

## Part 2 — ECC Key Generation

openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem

File sizes: rsa_private.pem = 1708 bytes, ecc_private.pem = 302 bytes. Ratio ≈ 5.7x (RSA larger).

ECC's security comes from the difficulty of the elliptic curve discrete logarithm problem, which is far harder to solve per bit than RSA's integer factorization problem — so a 256-bit ECC key gives security roughly equivalent to a 3072-bit RSA key. Smaller keys mean less computation and less bandwidth, which matters directly for MedDefense's constrained devices (BD Alaris pumps, Philips monitors) that have limited CPU and cannot afford RSA-level processing overhead for every handshake.

## Part 3 — The Hybrid Model

In the hybrid model, asymmetric encryption (RSA or ECC/ECDHE) is used only to establish a shared symmetric session key between two parties who have never communicated before, solving the key-distribution problem. Once that session key is agreed, all actual data is encrypted with a fast symmetric cipher such as AES-256-GCM. This combination is superior to using either method alone because asymmetric encryption is too slow and too size-limited (Part 1) to encrypt bulk data, while symmetric encryption alone cannot solve the problem of two strangers agreeing on a secret key over an untrusted network. On MedDefense's patient portal, when a patient connects over HTTPS, the TLS handshake (using RSA or, more commonly today, ECDHE) handles the key exchange, and once that shared secret is established, AES-GCM (a symmetric cipher) handles the encryption of the actual page and form data for the rest of the session.

## Part 4 — Key Length Table

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage |
|---|---|---|---|---|---|
| AES | Symmetric | 128/192/256-bit | 128/192/256-bit | Approved | Yes — AES-256-GCM recommended |
| RSA | Asymmetric | 2048/4096-bit | 112/152-bit | Approved (2048 min) | Yes — 2048 minimum, 4096 preferred |
| ECC | Asymmetric | P-256/P-384 | 128/192-bit | Approved | Yes — preferred for constrained devices |
| DES | Symmetric | 56-bit | ~56-bit | Deprecated | No — broken, must not be used |
| 3DES | Symmetric | 112-bit effective | ~80-bit | Deprecated (NIST 2023) | No — retired, do not use |
| ChaCha20-Poly1305 | Symmetric AEAD | 256-bit | 256-bit | Approved | Yes — good for low-power/no-AES-NI devices |
| RC4 | Stream | 40-128 bit | Broken | Prohibited | No — cryptographically broken |
