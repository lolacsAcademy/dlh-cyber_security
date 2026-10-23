
# Incident Timeline: IR-2026-0420-01

## Header

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52:00Z
- declared_by: On-call IR Analyst (student)
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Mike Torres, Network Engineer
- timeline_policy: Append-only; all timestamps UTC

## Legend

- OBSERVATION: Reported or recorded event.
- DECISION: Incident response decision and rationale.
- ACTION: Operation performed during response.
- COMMUNICATION: Information sent or received.
- EVIDENCE: Preserved artifact and acquisition details.

## Entries

- 2026-04-20T19:43:22Z | OBSERVATION | Mike Torres | Reported nurse's concerns about slow CS-WS-101 and possibly changed filenames; file changes not verified | source=torres_call_transcript.md | certainty=reported_unverified

- 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres / Wazuh SIEM | Reported service-installation alert wz-edr-200214 on CS-WS-104, CS-WS-107 and CS-WS-112 within a 12-minute window; exact individual alert timestamps not provided | source=torres_call_transcript.md | certainty=reported

- 2026-04-20T19:52:00Z | DECISION | On-call IR Analyst | Declared IR-2026-0420-01 at initial SEV2 due to suspected multi-host compromise and clinical service degradation; patient-safety impact, ransomware and data exposure remain unconfirmed | source=ir_activation.md | certainty=exercise_decision
