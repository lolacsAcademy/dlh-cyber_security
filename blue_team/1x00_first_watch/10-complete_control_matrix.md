# MedDefense — Complete Control Matrix

## Part 1: Control Registry (18 controls)

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|---|---|---|---|---|---|---|
| C-001 | Perimeter Firewall Policy | Technical | Preventive | Internal network, all servers | Adequate | Task 4, Artifact 1 — DMZ isolation works, but VPN rules allow ALL services, no egress filtering |
| C-002 | Firewall Traffic Logging | Technical | Detective | Perimeter traffic | Weak | Task 5 G-001 — 30-day local only, not centralized or alerted |
| C-003 | SSH Key-Based Auth | Technical | Preventive | ehr-srv-01 only | Adequate | Task 4, Artifact 2 — strong where applied, but only 1 of many Linux servers |
| C-004 | SSH Verbose Logging | Technical | Detective | ehr-srv-01 only | Adequate | Task 4, Artifact 2 — logs exist but same narrow scope |
| C-005 | Account Lockout Threshold | Technical | Preventive | Windows/AD accounts | Adequate | Task 4, Artifact 3 — Windows only via GPO, Linux configured individually |
| C-006 | Sophos Endpoint AV | Technical | Preventive | Windows workstations only | Weak | Task 4, Artifact 4 — 0% server/Linux coverage; missed the Task 2 cryptominer |
| C-007 | Veeam Nightly Backup | Technical | Corrective | 6 core VMs | Weak | Task 5 G-005 — co-located with production, DR never fully tested |
| C-008 | Windows Event Logging | Technical | Detective | Windows servers | Weak | Task 4, Artifact 8 — manual, reactive only |
| C-009 | Linux Syslog | Technical | Detective | Linux servers | Weak | Task 4, Artifact 8 — decentralized, no alerting |
| C-010 | Apache Logging | Technical | Detective | web-srv-01, billing-srv-01 | Weak | Task 4, Artifact 8 — passive only |
| C-011 | EHR Audit Log | Technical | Detective | EHR access trail | Adequate | Task 4, Artifact 8 — exists, but 48-hour export delay |
| C-012 | Password Policy | Administrative | Preventive | All accounts | Adequate | Task 4, Artifact 3 — reasonable, but no MFA, inconsistent enforcement |
| C-013 | Security Awareness Training | Administrative | Preventive | All staff | Weak | Task 4, Artifact 7 — 58% completion at Westside, no phishing sims |
| C-014 | Onsite Security Guard | Physical | Preventive | Central main entrance | Weak | Task 4, Artifact 6 — weekdays only, no patrol, did not stop Task 3 findings |
| C-015 | CCTV Camera System | Physical | Detective | Central/Westside entrances | Weak | Task 4/5 — zero coverage of server room, closets, admin wing |
| C-016 | Badge Access Control | Physical | Preventive | Server room, restricted doors | Weak | Task 3, Obs 1 — same generic badge for all staff, no visitor log |
| C-017 | HQ Site-to-Site VPN | Technical | Preventive | HQ-to-Central traffic | Adequate | Task 0 — properly configured, but ACLs never audited |
| C-018 | Westside Site-to-Site VPN | Technical | Preventive | Westside-to-Central traffic | Weak | Task 0 — runs through a consumer-grade router, no firewall |
## Part 2: Updated Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| Technical | 6 (Adequate–Weak) | 6 (Weak) | 1 (Weak) | 0 (gap) | 0 (gap) |
| Administrative | 2 (Adequate–Weak) | 0 (gap) | 0 (gap) | 0 (gap) | 0 (gap) |
| Physical | 2 (Weak) | 1 (Weak) | 0 (gap) | 0 (gap) | 0 (gap) |

## Part 3: Control Coverage Map — Top 5 Critical Assets

| Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|---|---|---|---|---|---|
| Infusion Pumps | None specific (perimeter firewall only) | None | None (explicitly excluded from backup) | None | Unprotected |
| EHR System | C-001, C-003, C-005, C-012 | C-004, C-009, C-011 | C-007 | None | Partially Protected |
| Domain Controllers | C-001, C-005, C-012 | C-008 | C-007 (ad-dc-01 only; ad-dc-02 excluded) | None | Partially Protected |
| PACS Server | C-001 (perimeter only) | C-008 (generic) | None (excluded from backup) | None | Under-Protected |
| billing-srv-01 | C-001, C-005, C-012 | C-009, C-010 | C-007 | None | Under-Protected |
