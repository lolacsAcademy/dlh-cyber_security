# Task 12 — The Legacy Systems

## System 1: Windows XP SP3 (WS-RAD-01, MRI Workstation)

**EOL Research:** Zero new CVEs were published against Windows XP in 2025 (confirmed via CVE tracking sites). This isn't good news — it means Microsoft and the security community have fully stopped analyzing this OS. The entire risk here is the pre-2014 backlog already found in this scan: MS08-067 (CVSS 10.0), BlueKeep (CVSS 9.8), and EternalBlue (CVSS 8.1) — the two most critical being MS08-067 and BlueKeep, both wormable and both listed in CISA KEV.

**Permanent Exposure:** EOL is categorically different from "unpatched" because unpatched implies a fix exists and simply hasn't been applied yet — a temporary, closeable gap. EOL means no fix will ever be released, for this or any future vulnerability discovered against this OS. Patching alone can never close this risk because there is nothing left to patch to.

**Scan Findings:** Finding 004 — all three CVEs (EternalBlue, BlueKeep, MS08-067) are exploitable specifically because this system is EOL; each has had a patch available for years, but Windows XP will never receive it.

**Compensating Controls (1x00 T6):** Four controls were proposed: (1) dedicated VLAN with firewall rules limited to PACS traffic only, (2) application whitelisting, (3) a documented risk-acceptance and review policy, (4) restricted physical access. Control 1 (network segmentation) was identified as the highest-priority single control. Do these adequately address the scan findings? Partially — segmentation would block the flat-network lateral movement that makes this host dangerous to the rest of MedDefense, and whitelisting would stop unauthorized payloads from running. But neither control removes the underlying vulnerabilities themselves; if an attacker reaches the workstation through the permitted PACS channel itself, these three CVEs remain fully exploitable. Recommendation: add network-level intrusion detection on the dedicated VLAN specifically tuned to SMB/RDP exploit signatures, since those are the exact protocols these CVEs use.

## System 2: Windows Server 2012 R2 (print-srv-01)

**EOL Research:** Two critical CVEs were published in the last 2 years that explicitly list Windows Server 2012 R2 among affected products: CVE-2025-24035 and CVE-2025-24045 (both March 2025, both CVSS 8.1, both RCE in Windows Remote Desktop Services). Neither will ever be patched on this host.

**Permanent Exposure:** Same principle as System 1 — these two RDS vulnerabilities were disclosed a decade after this OS stopped receiving updates, proving new critical flaws keep surfacing in old code long after support ends. No patching effort can close a risk that has no patch to apply.

**Scan Findings:** Finding 008 (PrintNightmare) — exploitable specifically because this is EOL; Print Spooler is confirmed running, and no fix is coming.

**Compensating Controls (1x00 T6):** Not covered — 1x00 T6 only addressed the MRI workstation, not print-srv-01. Recommended controls: disable the Print Spooler service if not strictly required, or restrict it to local-only printing; place this host on a restricted VLAN segment similar to the MRI approach, since it currently sits on the same flat server network as everything else.

## System 3: Ubuntu 18.04 LTS without ESM (billing-srv-01)

**EOL Research:** One CVE was found specifically tagged against Ubuntu 18.04 in the last 2 years: CVE-2025-26465 (February 2025, CVSS 6.8, OpenSSH host-key verification MITM flaw), confirmed as affecting the 18.04 openssh-ssh1 package. Notably, this host was NOT affected by the higher-profile RegreSSHion flaw (CVE-2024-6387) — Ubuntu's own advisory confirms 18.04's older OpenSSH version predates the vulnerable code, so not every EOL system is vulnerable to every new disclosure. The real critical exposure here is Finding 026's confirmed backlog of 47 unpatched kernel CVEs, none of which will ever be fixed without ESM enrollment.

**Permanent Exposure:** Standard security support ended June 2023; without ESM, this system stopped receiving OS-level patches entirely from that date forward. Every kernel or package CVE disclosed since then — 47 and counting — stays open permanently, with no patching path available.

**Scan Findings:** Findings 001, 002, 006, 009, 011, 026 all affect this host. Of these, Finding 011 (ESM not enrolled) and Finding 026 (47 unpatched kernel CVEs) are exploitable specifically because of EOL status. Findings 001 and 002 (Apache flaws) are application-level and could occur on a supported OS too, though the same lack of maintenance discipline behind the missing ESM likely explains why Apache itself is also outdated (2.4.29).

**Compensating Controls (1x00 T6):** Not covered — 1x00 T6 only addressed the MRI. Recommended controls: enroll in Ubuntu Pro/ESM immediately as a stopgap (this alone would close the 47-CVE kernel backlog without a full OS migration), combined with the network and SSH hardening already identified in Findings 003, 006, 009.

## Business Decision

If only one system can be migrated off EOL this quarter, it should be **billing-srv-01 (Ubuntu 18.04)**.

The MRI workstation (System 1) carries the highest technical risk and sits on a Critical-rated patient-safety asset category, but 1x00's own scenario constraints rule it out for this quarter: the manufacturer's certification is tied to this exact OS version, and replacing the $2.1M device outright is not a budget option — migrating it isn't realistically achievable in one quarter regardless of priority.

print-srv-01 (System 2) carries real EOL risk but supports a low-criticality function (printing), with no asset criticality rating anywhere near Critical or High, and no named appearance in any of the five 1x01 kill chains or the Threat Actor Matrix's primary targets.

billing-srv-01 (System 3) is rated Overall High in the Criticality Matrix, is explicitly named as the primary target of the Unskilled/Opportunistic actor in the Threat Actor Matrix specifically because it has already been compromised twice, and is the only EOL system in this report directly named in a formal kill chain (Kill Chain 3, tied to GAP-003). It also carries more scan findings than any other host (six). Unlike the MRI, migrating a general-purpose Linux server to a supported Ubuntu release is a standard, achievable technical project — making it both the highest-value and the most realistic migration target this quarter.
