# Task 6 — The Technical Proof

## Check 1: Certificate Inspection
Command:
openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

Output summary:
- Subject: CN=github.com
- Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
- Validity: Jul 3 2026 - Sep 30 2026
- Key Algorithm: id-ecPublicKey (256 bit)
- SAN: DNS:github.com, DNS:www.github.com

## Check 2: Hash Verification
Command:
echo "MedDefense firmware test" > firmware_test.txt && sha256sum firmware_test.txt
echo "line added" >> firmware_test.txt && sha256sum firmware_test.txt

Output:
Original: 57bb6c2010ced517197f5aa7485718f8c3da5cb65fd3d3f9ed044db6980137eb
Modified: e55d3f13681b4693a21cf86e815af94b2fa79d8478449a4343d579543fdea8b9

Hashes differ, confirming the file changed. Why it matters: without verifying the FortiOS firmware hash before install, a single altered byte in a tampered image produces a completely different hash and would go undetected without this check.
## Check 3: Exploit Research
Command: searchsploit fortigate / searchsploit fortios

Output: No entries for CVE-2023-27997/XORtigate in Exploit-DB. Closest match was an unrelated FortiOS SSL-VPN 7.4.4 issue on a different version range.

No public Exploit-DB/Metasploit entry exists for this CVE, but PoC code exists independently on GitHub and it's listed in CISA KEV as actively exploited. This shows patch urgency can't wait for a searchsploit result — a vulnerability can be under real, active attack before it ever gets a formal exploit-database entry.

## Check 4: System Audit
Command: sudo lynis audit system --quick

Output:
- Hardening Index: 61/100
- Warnings: none returned this run
- 48 suggestions logged (file integrity monitoring, malware scanner, auditd, firewall config among them)

Suggestion for billing-srv-01: install a file integrity monitoring tool (Lynis control FINT-4350) — billing-srv-01 has already been compromised twice (ransomware, then a cryptominer) with no detection in place; file integrity monitoring would have flagged both intrusions early.
