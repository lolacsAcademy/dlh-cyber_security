# Task 11 — The False Positives

## Finding 020 — OpenSSH PKCS#11 (backup-srv-01)

Finding ID: 020
Reported Vulnerability: CVE-2023-38408, CVSS 9.8, OpenSSH 8.9p1 PKCS#11 provider flaw on backup-srv-01.
Why It Is a False Positive: SecurePoint flagged this directly in the scan report. Exploitation requires ssh-agent to be running with PKCS#11 support forwarded to an attacker-controlled host — a specific precondition unlikely to exist in this server's normal operation.
Validation Method: Check sshd_config and ssh_config on backup-srv-01 for ForwardAgent/AllowAgentForwarding settings, and confirm with the team whether ssh-agent forwarding to any external host is actually used (e.g., during vendor remote sessions). If forwarding is disabled or never points outside the trusted network, the exploit precondition doesn't exist.
Risk of Acting on This FP: Emergency patching of the production backup server, possible service interruption to backup operations, and analyst time spent on this instead of Critical findings like 001, 003, or 031.
Risk of Not Validating: If ssh-agent forwarding to an external host actually does happen (e.g., a vendor support session), this becomes a genuine critical path into the backup server — dismissing it without checking could leave a real hole open.

## Finding 030 — TLS Certificate CN Mismatch (ehr-srv-01)

Finding ID: 030
Reported Vulnerability: The TLS certificate on ehr-srv-01 is issued for "ehr.meddefense.local," but some clients connect via IP address directly, triggering browser certificate warnings.
Why It Is a False Positive: The scan report's own description states this outright: "This is an operational issue, not a security vulnerability." A CN mismatch here doesn't create any new attacker capability — it's a usability inconsistency from clients using an IP instead of the hostname, not a flaw an attacker can exploit.
Validation Method: Confirm the certificate is valid, unexpired, and issued by a trusted CA for the correct hostname, and confirm the affected clients are only reaching the server by IP (not through a spoofed or attacker-controlled certificate).
Risk of Acting on This FP: Time spent reissuing a certificate to cover the IP address, or forcing a hostname-only access policy — effort better spent on Critical findings, when the real fix is simply updating internal DNS references.
Risk of Not Validating: If this gets dismissed as "just the usual CN mismatch" without checking, a genuine MITM or spoofed-certificate scenario could hide behind the same symptom and go unnoticed.

## Finding 027 — Windows Defender Antivirus Status

Finding ID: 027
Reported Vulnerability: "Windows Defender is not the primary endpoint protection on managed workstations."
Why It Is a False Positive: This is by design, not a gap — the finding itself notes Sophos Endpoint is the organization's deployed and intended AV/EDR solution. Defender not being primary is expected. (The separate detail in the same finding — 15 workstations showing Sophos as "inactive/not reporting" — is a real, distinct issue, not part of this false positive.)
Validation Method: Confirm through Sophos Central / IT asset management that Sophos is the officially sanctioned endpoint protection policy for these workstations, and that this was an intentional deployment decision.
Risk of Acting on This FP: Wasted effort re-enabling Windows Defender across hundreds of workstations that already run a functioning EDR, potentially causing conflicts from running two antivirus agents simultaneously.
Risk of Not Validating: If Sophos coverage turns out not to be properly licensed or maintained org-wide (separate from the 15 already-flagged inactive agents), dismissing this finding as "just Sophos being primary" could mean workstations are running with no real-time protection at all.

## Expected False Positive Rate

The scan report's own methodology notes state OpenVAS's typical false positive rate in this configuration is 5-10%. Applied to 31 findings, that's roughly 2 to 3 expected false positives — which lines up exactly with what this task asked us to find.

Manual validation before committing remediation resources is essential because a scanner only detects patterns (version strings, banners, configuration snapshots) — it can't see operational context like whether a feature is actually in use, whether a "vulnerable" service is protected by a compensating control, or whether the description itself flags the issue as non-exploitable in this environment (as with Finding 020 and Finding 030 here). Acting on unvalidated findings burns limited security staff time and can even cause outages from unnecessary emergency patching, while the time spent chasing false positives is time not spent on confirmed Critical findings that pose real risk.
