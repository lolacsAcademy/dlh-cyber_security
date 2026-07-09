# MedDefense — Security Control Inventory

## Control Inventory

Control ID: C-001
Control Name: Perimeter Firewall Policy (Default-Deny + DMZ Isolation)
Description: FortiGate 100F only permits inbound web traffic to web-srv-01 (DMZ) and denies all other unmatched traffic by default (Rule 5).
Category: Technical
Function: Preventive
Asset(s) Protected: Internal network, all servers behind the firewall
Source: Artifact 1

Control ID: C-002
Control Name: Firewall Traffic Logging
Description: FortiGate logs traffic per policy rule (logtraffic all/utm), retained locally for 30 days.
Category: Technical
Function: Detective
Asset(s) Protected: Perimeter network traffic
Source: Artifacts 1, 8

Control ID: C-003
Control Name: SSH Key-Based Authentication (ehr-srv-01)
Description: Password authentication disabled, public key authentication required, root login disabled.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01
Source: Artifact 2

Control ID: C-004
Control Name: SSH Verbose Authentication Logging (ehr-srv-01)
Description: SyslogFacility AUTH with LogLevel VERBOSE records all authentication attempts.
Category: Technical
Function: Detective
Asset(s) Protected: ehr-srv-01
Source: Artifact 2

Control ID: C-005
Control Name: Account Lockout Threshold
Description: Accounts lock for 30 minutes after 5 failed login attempts, enforced via AD Group Policy on Windows systems.
Category: Technical
Function: Preventive
Asset(s) Protected: Windows user/domain accounts
Source: Artifact 3

Control ID: C-006
Control Name: Sophos Endpoint Antivirus
Description: Signature-based protection blocking/quarantining malware on managed endpoints (88% of covered devices current).
Category: Technical
Function: Preventive
Asset(s) Protected: Windows workstations (partial: servers and Linux not covered)
Source: Artifact 4

Control ID: C-007
Control Name: Veeam Nightly Backup
Description: Full nightly backup of 6 core VMs to a local NAS, 14-day retention, enabling restoration after data loss.
Category: Technical
Function: Corrective
Asset(s) Protected: EHR app/DB, billing, AD DC, file server, web server
Source: Artifact 5

Control ID: C-008
Control Name: Windows Server Event Logging
Description: Windows servers log events to Event Viewer, reviewed manually when an issue occurs.
Category: Technical
Function: Detective
Asset(s) Protected: Windows servers (ad-dc-01/02, pacs-srv-01, file-srv-01, print-srv-01)
Source: Artifact 8

Control ID: C-009
Control Name: Linux Syslog
Description: Linux servers write standard syslog events to /var/log, not centralized.
Category: Technical
Function: Detective
Asset(s) Protected: Linux servers (ehr-srv-01, ehr-db-01, billing-srv-01, backup-srv-01)
Source: Artifact 8

Control ID: C-010
Control Name: Apache Web Server Logging
Description: Access/error logs rotate weekly via logrotate, 4 weeks retained.
Category: Technical
Function: Detective
Asset(s) Protected: web-srv-01, billing-srv-01
Source: Artifact 8

Control ID: C-011
Control Name: EHR Application Audit Log
Description: Vendor-managed audit log of EHR access/activity; exports available on request (48-hour turnaround).
Category: Technical
Function: Detective
Asset(s) Protected: EHR patient data / access trail
Source: Artifact 8

Control ID: C-012
Control Name: Password Policy
Description: Documented requirements: 8-character minimum, complexity, 90-day rotation, 5-password history.
Category: Administrative
Function: Preventive
Asset(s) Protected: All employee/contractor/vendor accounts
Source: Artifact 3

Control ID: C-013
Control Name: Annual Security Awareness Training
Description: "CyberSafe Basics" module covering password hygiene, phishing, physical security awareness, and reporting.
Category: Administrative
Function: Preventive
Asset(s) Protected: All staff (human attack surface)
Source: Artifact 7

Control ID: C-014
Control Name: Onsite Security Guard
Description: Uniformed guard at Central's main entrance, Mon–Fri 7AM–7PM, performs visitor registration and badge verification.
Category: Physical
Function: Preventive
Asset(s) Protected: Central main entrance
Source: Artifact 6

Control ID: C-015
Control Name: CCTV Camera System
Description: 4 analog cameras at Central (entrance, ER, garage) recording to a 30-day DVR; 1 camera at Westside recording to a 48-hour SD card.
Category: Physical
Function: Detective
Asset(s) Protected: Central entrances/garage, Westside entrance
Source: Artifact 6

## Control Summary Matrix

| | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| Technical | C-001, C-003, C-005, C-006 | C-002, C-004, C-008, C-009, C-010, C-011 | C-007 | — | — |
| Administrative | C-012, C-013 | — | — | — | — |
| Physical | C-014 | C-015 | — | — | — |

Gaps observed: no Administrative Detective or Corrective controls, no Physical Corrective control, and no formal Compensating or Deterrent control is evidenced anywhere in the artifacts. These empty cells represent real gaps in the current control landscape, not omissions in this inventory.
