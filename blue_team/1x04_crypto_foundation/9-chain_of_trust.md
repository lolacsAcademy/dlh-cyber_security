# Task 9 — The Chain of Trust

MedDefense Health Systems — 1x04 Task 9

## Part 1 — Capture the Full Chain

Site: github.com. Chain: 3 certificates.

**0 — Leaf**
- Subject: CN=github.com
- Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36

**1 — Intermediate**
- Subject: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36 (matches leaf's Issuer)
- Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46

**2 — Root**
- Subject: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46 (matches intermediate's Issuer)
- Issuer: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority

Each certificate's Issuer matches the next certificate's Subject — this is how trust chains from leaf to root.

## Part 2 — Manual Chain Verification

openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem
→ leaf.pem: OK

openssl verify -CAfile root.pem leaf.pem
→ error 20 at 0 depth lookup: unable to get local issuer certificate / leaf.pem: verification failed

This shows a client can't validate a leaf cert with only the root — it needs the intermediate to bridge the two, since trust stores hold roots, not every intermediate CA. Servers that omit the intermediate break validation for real visitors.

## Part 3 — Revocation Mechanisms

**CRL:** Full list of revoked serial numbers published periodically, downloaded and checked locally by the client. Limitation: grows large, updates infrequently, so a fresh revocation may not appear until the next scheduled update.

**OCSP:** Client queries a CA responder for one certificate's real-time status instead of downloading the whole list — faster, less bandwidth. OCSP Stapling has the server pre-fetch a signed OCSP response and attach it to the TLS handshake, so the client gets status without contacting the CA.

**MedDefense — portal key compromised (per 1x03 T25):**
1. Contact the CA, request emergency revocation
2. CA revokes cert, updates CRL/OCSP
3. Generate a new key pair — never reuse the compromised key
4. Submit new CSR
5. CA issues new certificate
6. Deploy new cert/key, remove the old one
7. Verify revocation status and new cert serving correctly
8. Investigate how the key leaked into Git and remediate (secret scanning, history purge, .gitignore)

## Part 4 — Trust Store Exploration

Location: /etc/ssl/certs/
Root CAs trusted: 304
Inspected: DigiCert Global Root CA — Validity: Nov 10 2006 – Nov 10 2031 (25-year lifespan)

Surprising compared to Task 8's leaf certs (200-day max under 2026 rules) — but roots stay offline and rarely sign directly, so their exposure risk is far lower than an internet-facing leaf certificate.
