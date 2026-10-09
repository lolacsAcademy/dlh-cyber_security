# Incident Timeline: IR-20260414-01

## Header

- incident_id: IR-20260414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: On-call SOC Analyst
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: On-call SOC Analyst

## Legend

- OBSERVATION: A fact recorded in an alert or log.
- DECISION: An incident response choice and its rationale.
- ACTION: An operation performed during the response.
- COMMUNICATION: Information sent or received.
- EVIDENCE: A preserved artifact with its hash and storage path.

## Entries

- 2026-04-13T18:13:44Z | OBSERVATION | Proxy logger | User dmarsh accessed an Outlook email message on WST-WS-031 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy logger | User dmarsh accessed a suspicious Microsoft-themed login page, returning HTTP 200 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | Proxy logger | User dmarsh sent an HTTP POST to the suspicious login site's /auth/submit endpoint; submitted content is unknown | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | Proxy logger | User dmarsh requested /auth/drop/update.zip from the suspicious site; HTTP 200 recorded | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | WazuhEDR | powershell.exe started as MEDDEFENSE\dmarsh on WST-WS-031 with hidden-window and encoded-command arguments | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | WazuhEDR | PowerShell spawned msbuild.exe using the temporary file C:\Users\dmarsh\AppData\Local\Temp\update.xml | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | WazuhEDR | MSBuild established outbound TCP connection to 185.220.101.47:443, identified by internal threat intelligence as a Tor exit relay | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | WazuhEDR rule wz-edr-100041 | Alert A-20260414-9841 fired for suspicious PowerShell-to-MSBuild execution and outbound communication on clinical workstation WST-WS-031 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Incident IR-20260414-01 declared at SEV2 due to suspicious execution and confirmed external connectivity on a high-criticality clinical workstation; patient data exposure and wider compromise remain unconfirmed | source=alert_A-20260414-9841.json | certainty=confirmed
- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Proposed quarantine VLAN isolation for WST-WS-031 after evidence preservation; approval pending from James Chen. See containment_decision.md for alternatives and rationale | source=containment_decision.md | certainty=confirmed
