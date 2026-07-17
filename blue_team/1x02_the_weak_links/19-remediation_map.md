# Task 19 — The Remediation Map

## Finding 031 - Ghostcat (ehr-srv-01)
Response Type: Configuration Change (fastest fix; full patch tracked separately)

Change Description: Disable the Tomcat AJP connector on port 8009 if not required, or set a requiredSecret/restrict address to localhost per Apache's own advisory, since MedDefense's setup does not need AJP exposed to the network.
Impact Assessment: No clinical impact expected — AJP is an internal connector protocol, not used by end users directly; EHR web access over HTTPS is unaffected.

Timeline: Immediate
Owner: IT (with Security sign-off)
Cost Estimate: $0-1K

## Finding 003 - PostgreSQL Exposure (ehr-db-01)
Response Type: Configuration Change

Change Description: Restrict pg_hba.conf to accept connections only from ehr-srv-01's specific IP, and add a host-based firewall rule dropping all other traffic to port 5432, per the scan's own recommendation.
Impact Assessment: EHR application traffic (the only legitimate consumer) is unaffected; any other host currently reaching the DB directly (none should be) would lose access.

Timeline: Immediate
Owner: IT
Cost Estimate: $0-1K

## Finding 004 - Windows XP EOL Cluster (WS-RAD-01)
Response Type: Exception

Justification: The manufacturer's FDA certification is tied to this exact OS version; replacing the $2.1M MRI device is not currently budgeted, and the OS cannot be patched or upgraded without voiding certification (per 1x00 T6's documented constraints).
Review Date: Next fiscal year budget cycle, or sooner if the device reaches end of its 12-year operational lifespan.
Monitoring: Deploy the dedicated VLAN and application whitelisting proposed in 1x00 T6 (not yet implemented per the Control Registry) alongside network intrusion detection tuned to SMB/RDP exploit signatures on that segment.

Timeline: 90 days (for compensating controls; the underlying exception has no remediation timeline)
Owner: Security (controls) / Clinical Engineering (device lifecycle)
Cost Estimate: $10-50K (VLAN + IDS deployment; excludes eventual device replacement)

## Finding 001 - CVE-2021-44790 (billing-srv-01)
Response Type: Patch

Patch Source: Apache HTTP Server upgrade to 2.4.52 or later (httpd.apache.org/security/vulnerabilities_24.html)
Prerequisites: Test the upgrade against the billing application in a staging environment first, given prior instability on this host; schedule a maintenance window outside billing cycle processing hours; take a full backup/snapshot before applying.
Rollback Plan: Revert to the pre-patch snapshot if the billing application fails to start or behaves incorrectly post-upgrade.
Operational Risk: The billing application may have compatibility issues with the newer Apache version given how outdated the current install is; possible short downtime during the restart.

Timeline: 7 days
Owner: IT
Cost Estimate: $0-1K

## Finding 002 - CVE-2019-0211 (billing-srv-01)
Response Type: Patch

Patch Source: Same Apache 2.4.52 upgrade as Finding 001 resolves this CVE as well (fixed since 2.4.39).
Prerequisites: Covered by the same maintenance window and backup as Finding 001 — apply together, not separately.
Rollback Plan: Same snapshot rollback as Finding 001.
Operational Risk: None beyond what's already assessed for Finding 001's upgrade.

Timeline: 7 days (same window as Finding 001)
Owner: IT
Cost Estimate: $0 (covered by Finding 001's patch)

## Finding 015 - NAS-01 + CVE-2024-10441
Response Type: Patch

Patch Source: Synology DSM update to 7.2.2-72806-1 or later (synology.com security advisory)
Prerequisites: Confirm current DSM build number first; back up the NAS configuration before updating; schedule during a low-usage window since backup jobs may pause during the update.
Rollback Plan: Synology supports rolling back to the previous DSM version via its update history if the new build causes issues.
Operational Risk: Backup jobs in progress during the update window could be interrupted; verify no active backup runs are scheduled during the maintenance window.

Timeline: 7 days
Owner: IT
Cost Estimate: $0-1K

## Finding 007 - LDAP Relay / SMBv1 (ad-dc-01)
Response Type: Configuration Change

Change Description: Enable LDAP signing (require it, not just support it) on the domain controller, and disable SMBv1 entirely per Microsoft's guidance.
Impact Assessment: Any legacy application or device still relying on unsigned LDAP or SMBv1 would break — needs an inventory check first to confirm nothing critical (e.g., older medical devices) depends on SMBv1 before disabling.

Timeline: 30 days (allowing time for the legacy-dependency check)
Owner: IT
Cost Estimate: $0-1K

## Finding 010 - CVE-2020-25165 / Default Credentials (BD Alaris)
Response Type: Configuration Change (immediate) + Compensating Control (underlying CVE)

Change Description: Change default admin/admin credentials on all 7 pumps' web management interfaces immediately — this is the higher-urgency, self-inflicted gap.
Impact Assessment: No clinical impact — credential change doesn't affect pump operation.

Control Description: For the underlying CVE-2020-25165 network session flaw itself, implement BD's recommended mitigation: firewall separation between the PC Unit and Systems Manager, restrict the wireless segment per BD's bulletin.
Residual Risk: BD's bulletin doesn't describe a firmware fix, only mitigations — the underlying flaw remains until BD releases one; network isolation reduces but doesn't eliminate exposure.

Timeline: Immediate (credential change) / 30 days (network isolation)
Owner: IT (credentials) / Security + Clinical Engineering (isolation)
Cost Estimate: $0-1K (credentials) / $1-10K (network segmentation for medical IoT)
