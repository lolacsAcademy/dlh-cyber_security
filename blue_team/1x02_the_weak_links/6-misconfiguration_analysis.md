# Task 6 — The Misconfiguration Findings

## Finding 003

Finding ID: 003
Host: ehr-db-01 (10.10.2.11, A-02)
Misconfiguration: PostgreSQL accepts connections from the entire internal network (`pg_hba.conf: host all all 10.10.0.0/16 md5`, `listen_addresses = '*'`), with no firewall restricting access to port 5432. The database holds protected health information.
Why No CVE: PostgreSQL is functioning exactly as it was configured to. There is no software flaw being exploited — the product behaves correctly according to its settings; the settings themselves are wrong.
Severity Assessment: Critical — direct, unauthenticated-at-the-network-layer reachability to the PHI database from any compromised host on a flat 10.10.0.0/16 network.
Cross-Reference 1x00: Asset Registry (1x00 T7) already flags this exact port exposure on A-02 as a "Task 4 gap" — this is a known, pre-existing issue, not a new discovery.
Comparable CVE Risk: CVE-2020-1938 "Ghostcat" (Finding 031) also exposes database credentials via file read on the EHR stack. Ghostcat needs a specific AJP connector condition; this misconfiguration needs nothing but network reachability, making it arguably the more reliable path to the same PHI database.

## Finding 007

Finding ID: 007
Host: ad-dc-01 (10.10.2.20, A-05)
Misconfiguration: LDAP signing not required on the domain controller, enabling LDAP relay attacks; SMBv1 also enabled on the same host.
Why No CVE: These are default-off security hardening settings that were never turned on, not a coding defect in Active Directory itself.
Severity Assessment: High — on a flat network, any compromised host can reach the DC and attempt a relay attack against it.
Cross-Reference 1x00: Matches the recurring flat-network theme documented across the Asset Registry (1x00 T7), e.g. A-13 workstations explicitly noted as "same flat network as servers and medical devices" — no segmentation to contain this.
Comparable CVE Risk: CVE-2021-34527 "PrintNightmare" (Finding 008) also targets domain-level compromise. Unlike PrintNightmare, exploiting LDAP relay + SMBv1 needs no CVE-tracked exploit code at all — just a position on the flat network.
## Finding 014

Finding ID: 014
Host: Westside Clinic perimeter router (10.10.10.1, A-28)
Misconfiguration: Consumer-grade Netgear router used as the enterprise perimeter device; it also terminates the site-to-site IPSec VPN into MedDefense Central.
Why No CVE: The device is doing what a consumer router does. The problem is using a non-enterprise product in a role it was never designed for — an architecture decision, not a bug.
Severity Assessment: High (raised above the scan's Medium rating) — this single consumer device is a single point of failure for the entire Central-to-Westside network link; compromising it gives a direct tunnel into Central.
Cross-Reference 1x00: Asset Registry (1x00 T7) flags this same device with a "Task 0" note: "also runs the site-to-site VPN."
Comparable CVE Risk: CVE-2019-0708 "BlueKeep" (Finding 004) is a single point of complete host compromise. This router is a single point of complete network-link compromise — arguably broader impact, since it affects every host that traverses the VPN, not just one workstation.

## Finding 015

Finding ID: 015
Host: NAS-01 (10.10.2.41, A-10)
Misconfiguration: Synology DSM management interface reachable from the entire internal network on ports 5000/5001; backup data stored unencrypted.
Why No CVE: The web interface is working as intended; it was simply never restricted to admin-only IPs, and encryption-at-rest was never enabled. Both are configuration choices.
Severity Assessment: Medium — matches the scan; requires internal network access first, and directly threatens confidentiality of backups (not availability).
Cross-Reference 1x00: Asset Registry (1x00 T7) flags NAS-01 as sharing the "same room/rack as production — single point of failure" under a "Task 4/5" note.
Comparable CVE Risk: CVE-2021-44790 (Finding 001) also threatens data confidentiality/integrity. Task 4
## Finding 016

Finding ID: 016
Host: Philips IntelliVue patient monitors (10.10.3.10-32, A-18)
Misconfiguration: Web management interfaces on 13 patient monitors reachable from the entire network, with no authentication beyond the (flat, unsegmented) network layer.
Why No CVE: This is the vendor's default deployment behavior operating as designed; the gap is that MedDefense never restricted network access to these interfaces.
Severity Assessment: High (raised above the scan's Medium rating) — these are life-safety devices; unauthorized access to monitor configuration has direct patient-safety implications, not just data risk.
Cross-Reference 1x00: Directly stated in Asset Registry (1x00 T7) on A-18: "Management interface exposed network-wide."
Comparable CVE Risk: CVE-2020-25165 (BD Alaris pump, Finding 010) is a DoS-only CVE on similar clinical IoT. This misconfiguration is arguably worse: it's a full open management interface, not just a denial-of-service condition, on the same class of critical-care device.

## Finding 023

Finding ID: 023
Host: ~280 nurse station / clinical workstations (10.10.1.20-42, A-13)
Misconfiguration: No Group Policy restriction on USB mass storage devices.
Why No CVE: Windows and Group Policy both function correctly; USB restriction is an optional control that was simply never configured.
Severity Assessment: Low — matches the scan; requires physical proximity or insider access, not remotely exploitable.
Cross-Reference 1x00: A-13 in the Asset Registry (1x00 T7) is documented as being on the "same flat network as servers and medical devices" — once malware lands via USB on any of these 280 endpoints, the flat network gives it a direct path everywhere else.
Comparable CVE Risk: CVE-2017-0144 "EternalBlue" (Finding 004) needs network reachability and a working exploit. Unrestricted USB access bypasses every network-based control entirely — a much simpler, harder-to-detect initial-access vector across 280 machines at once.
## Why "Our CVE scan shows nothing critical, we are secure" is dangerous false assurance

A CVE-based scan only measures software flaws that have been formally identified, assigned an ID, and cataloged — it says nothing about how existing, correctly-functioning software is configured. In this scan alone, the PHI database, the site-to-site VPN router, the backup NAS, and 13 patient monitors are all directly exposed with no CVE attached to any of them, several rated equal to or more dangerous than the CVE-backed findings in this same report. Real-world incidents like the 2017 MongoDB ransomware wave (28,000 databases, zero CVEs) and the 2019 Capital One breach (a misconfigured WAF rule) show this isn't theoretical — misconfigurations account for some of the largest breaches on record. A "clean" CVE scan only means no known software bugs were found; it says nothing about whether the network is flat, whether defaults were hardened, or whether critical interfaces are exposed to anyone who reaches the network. Treating that as "secure" leaves an organization blind to exactly the class of risk most attackers actually use.
