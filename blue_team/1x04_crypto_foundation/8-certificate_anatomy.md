# Task 8 — The Certificate Anatomy

MedDefense Health Systems — 1x04 Task 8

## Part 1 — Inspect Three Real Certificates

**1. letsencrypt.org (Let's Encrypt)**
- Subject: CN=letsencrypt.org
- Issuer: C=US, O=Let's Encrypt, CN=YE2
- Validity: Jul 6 2026 – Oct 4 2026
- Serial: 05:05:bb:29:ef:e3:ee:15:2b:a3:e9:e6:87:28:10:b5:fe:b9
- Sig Algorithm: ecdsa-with-SHA384
- Public Key: id-ecPublicKey, 256-bit, P-256
- SAN: cp.letsencrypt.org, cp.root-x1.letsencrypt.org, cps.letsencrypt.org, cps.root-x1.letsencrypt.org, lencr.org, letsencrypt.com, letsencrypt.org, www.lencr.org, www.letsencrypt.com, www.letsencrypt.org
- Key Usage: Digital Signature (critical). EKU: TLS Web Server Authentication
- AIA: CA Issuers - http://ye2.i.lencr.org/ (no OCSP; CRL at http://ye2.c.lencr.org/58.crl)

**2. github.com (Sectigo — commercial CA)**
- Subject: CN=github.com
- Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
- Validity: Jul 3 2026 – Sep 30 2026
- Serial: 72:01:0e:03:f4:a0:67:fe:4e:79:62:66:43:07:18:f6
- Sig Algorithm: ecdsa-with-SHA256
- Public Key: id-ecPublicKey, 256-bit, P-256
- SAN: github.com, www.github.com
- Key Usage: Digital Signature (critical). EKU: TLS Web Server Authentication
- AIA: CA Issuers - http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt; OCSP - http://ocsp.sectigo.com

**3. expired.badssl.com (broken — COMODO)**
- Subject: OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com
- Issuer: C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA
- Validity: Apr 9 2015 – Apr 12 2015 (expired over a decade ago)
- Serial: 4a:e7:95:49:fa:9a:be:3f:10:0f:17:a4:78:e1:69:09
- Sig Algorithm: sha256WithRSAEncryption
- Public Key: rsaEncryption, 2048-bit
- SAN: *.badssl.com, badssl.com
- Key Usage: Digital Signature, Key Encipherment (critical). EKU: TLS Web Server Authentication, TLS Web Client Authentication
- AIA: CA Issuers - http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt; OCSP - http://ocsp.comodoca.com

## Part 2 — The Broken Certificate

- Validity ended Apr 12, 2015 — over a decade expired
- Browser error: Chrome shows NET::ERR_CERT_DATE_INVALID; Firefox shows SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE
- Risk: no assurance the connection is still genuinely trusted/encrypted; could be neglect or an active MITM attempt
- Recommendation: do not proceed — for a healthcare login handling PHI, treat this as a stop sign

## Part 3 — MedDefense Certificate Profile

- Type: OV (Organization Validation) — verifies MedDefense's legal identity, not just domain control; EV not justified since browsers no longer visually distinguish it
- CA: Established commercial CA (DigiCert or Sectigo) — better support/responsiveness than free DV-only CAs, given the existing cert-tracking failure (Finding 013)
- SAN: portal.meddefense.com, www.portal.meddefense.com — only the hostnames actually in use
- Key algorithm: ECDSA P-256 — matches current CA defaults, smaller/faster than RSA-2048 at equivalent security (consistent with T2 findings)
- Validity: 200 days maximum — current CA/Browser Forum ceiling as of March 2026; pair with automated renewal (ACME) to fix the root cause of Finding 013
- Wildcard vs. single-domain: single-domain/small SAN list preferred — a wildcard's compromised key would expose every subdomain at once, too much blast radius for the portal
