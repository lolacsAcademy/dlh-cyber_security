# Task 11 — The TLS Audit

MedDefense Health Systems — 1x04 Task 11

## Part 1 — SSL Labs Analysis

**Site 1: cloudflare.com — Grade B**
- Protocols: TLS 1.3 Yes, TLS 1.2 Yes, TLS 1.1 Yes, TLS 1.0 Yes — legacy protocols still enabled, primary cause of the B grade
- Key exchange: X25519/ECDH, equivalent to 3072-bit RSA — strong where forward secrecy suites used, but several non-FS RSA suites also offered (WEAK-flagged)
- Cipher suites: strong TLS 1.3/1.2 AEAD suites present, but many legacy CBC and non-FS RSA suites also offered across TLS 1.0/1.1/1.2, including 3DES
- Certificate: dual RSA-2048 and EC-256 certs, both trusted, valid, CT-logged, CAA configured, chain issues: none
- Warning: TLS 1.0/1.1 support is the main weakness dragging the grade down from A+ to B

**Site 2: www.ssllabs.com — Grade A+**
- Protocols: TLS 1.3 Yes, TLS 1.2 Yes, TLS 1.1 No, TLS 1.0 No — only modern protocols enabled
- Key exchange: X25519/DH 2048-bit, all forward-secret suites
- Cipher suites: TLS 1.3 AEAD suites only for 1.3; TLS 1.2 offers strong AEAD suites first, legacy CBC suites present but marked WEAK and deprioritized
- Hardening confirmed: BEAST mitigated, POODLE/Zombie POODLE/GOLDENDOODLE/Sleeping POODLE not vulnerable, downgrade attack prevention via TLS_FALLBACK_SCSV, no compression, no RC4, no Heartbleed/Ticketbleed/ROBOT, Forward Secrecy Robust, HSTS enabled with max-age=31536000
- No warnings of note — clean, fully hardened configuration

## Part 2 — MedDefense Portal Assessment

Predicted grade: C or lower, based on Finding 005 (TLS 1.0 enabled alongside TLS 1.2) and Finding 013 (certificate near expiration).

- TLS 1.0 support alone caps most SSL Labs scores well below A — same issue that dragged cloudflare.com to a B, MedDefense's case is likely worse since TLS 1.3 support isn't confirmed at all
- No TLS 1.3 confirmed — missing the modern protocol entirely, unlike both tested examples
- Certificate nearing expiration (Finding 013, 18 days at time of assessment) — SSL Labs flags near-expiry certs as a warning, further reducing the grade
- HSTS status unknown/not confirmed in prior findings — if absent, removes another grade-boosting factor present in the A+ example
- Cipher suite configuration undocumented beyond protocol versions in Finding 005 — if legacy CBC/RC4/3DES suites are also enabled (as seen in the B-rated case), grade would drop further toward C or D

## Part 3 — The Hardened Configuration

Nginx format:

ssl_protocols TLSv1.2 TLSv1.3;
→ Only TLS 1.2 and 1.3 — removes TLS 1.0/1.1 entirely, directly closing Finding 005.

ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
→ ECDHE for forward secrecy (matches T4's DH/MITM lesson), AEAD-only (GCM/ChaCha20-Poly1305, no CBC) to avoid padding-oracle-class attacks, ECDSA to match the portal's P-256 key from Task 8/10.

ssl_prefer_server_cipher_order on;
→ Server enforces its own cipher order rather than trusting the client, preventing steering toward a weaker mutually-supported suite.

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
→ HSTS with a 2-year max-age (doubled from the A+ example, appropriate for a healthcare portal) forces browsers to always use HTTPS, closing the downgrade window described in Part 4.

ssl_session_tickets off;
→ Session tickets disabled — ticket keys can persist on disk longer than the certificate's own key rotation and can undermine forward secrecy if compromised or reused across restarts.

ssl_session_cache shared:SSL:10m;
→ Session ID caching kept (safer than tickets) to preserve performance for 800 daily connections without the ticket-key exposure risk.

ssl_stapling on;
ssl_stapling_verify on;
→ OCSP stapling — server pre-fetches its own revocation status, giving clients faster, more private revocation checking (following the Task 9 OCSP Stapling lesson).

## Part 4 — The Downgrade Attack

A TLS downgrade attack exploits a server that still accepts multiple protocol versions: an attacker positioned on the network path intercepts the initial handshake and manipulates it — for example by stripping the higher-version options from the ClientHello — so the server and client end up agreeing to use the weakest protocol both sides still support, here TLS 1.0. Once negotiation is forced down to TLS 1.0, the attacker can then exploit known weaknesses in that older protocol (such as BEAST or POODLE-class attacks) that don't exist in TLS 1.2/1.3. If MedDefense's portal supports both TLS 1.0 and TLS 1.2, an on-path attacker performing exactly this manipulation could force a connecting patient's browser down to TLS 1.0 without either side necessarily noticing. The simplest and most complete prevention is to disable TLS 1.0 (and 1.1) on the server entirely, as done in the Part 3 configuration — if the weak protocol was never offered in the first place, there's nothing to downgrade to.
