# Task 10 — The CSR Workshop

MedDefense Health Systems — 1x04 Task 10

## Part 1 — Key Generation Decision

Chosen: ECC P-256. Security equivalent to roughly RSA-3072 but far less CPU cost per TLS handshake — matters at 800 patient connections/day. Broad compatibility across modern browsers/devices. Matches the Task 6 Algorithm Reference Table recommendation.

openssl ecparam -genkey -name prime256v1 -out portal_key.pem
→ Key generated successfully.

## Part 2 — CSR Generation

Config (openssl.cnf): CN=portal.meddefense.local, O=MedDefense Health Systems, OU=Information Technology, L=San Francisco, ST=California, C=US, SAN: portal.meddefense.local, www.portal.meddefense.local, patientportal.meddefense.local

openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
→ CSR generated successfully.

## Part 3 — CSR Inspection

openssl req -text -noout -in portal.csr

Subject: C=US, ST=California, L=San Francisco, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local
Public Key: id-ecPublicKey, 256-bit, P-256
SAN confirmed: DNS:portal.meddefense.local, DNS:www.portal.meddefense.local, DNS:patientportal.meddefense.local
Signature Algorithm: ecdsa-with-SHA256

All fields verified correct — CN, organization details, and all 3 SAN entries present as required.

## Part 4 — The Full Lifecycle

1. CSR generated (done) — portal_key.pem, portal.csr
2. Submission to CA: commercial OV CA (per Task 8 profile), not Let's Encrypt — healthcare portal needs Organization Validation
3. Validation process: CA verifies domain control plus MedDefense's legal business identity for OV
4. Certificate issuance: CA signs the CSR's public key, returns cert plus intermediate chain
5. Installation on the web server: deploy new cert, private key, and chain to the portal server, replacing the expiring one
6. Verification that the new certificate is serving correctly: openssl s_client against the live portal to confirm the new cert serves and chain validates
7. Decommission of the old certificate: remove old cert/key once new one is confirmed live; revoke old cert if key no longer needed
8. Monitoring for the next renewal: automated expiry alerts (30/14/7 days out), move to ACME automated renewal to prevent a repeat of Finding 013

## Script

See 10-generate_csr.sh in this directory — automates steps 1-3 (key generation, CSR creation, inspection).
