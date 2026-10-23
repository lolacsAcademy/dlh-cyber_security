
# IR Activation: IR-2026-0420-01

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52:00Z
- declared_by: On-call IR Analyst (student)
- initial_severity: SEV2
- severity_reasoning: >
    Suspected malware affecting multiple Main Site clinical
    workstations, with severe scheduling-server degradation.
    WinHealthSvc was flagged on three workstations.
    Possible file encryption on CS-WS-101 remains unverified.
    Clinical impact requires urgent assessment. No confirmed
    full outage, high patient-safety impact, or data exposure
    currently establishes SEV1 under the severity matrix.
- playbook_activated: >
    Incident response activation and triage under the
    MedDefense IR program. Existing PB-CLIN-002 is
    radiology-specific and PB-CRED-001 is credential-specific;
    neither directly matches this incident.
- ir_commander: James Chen
- technical_lead: Robert Kim
- executive_sponsor: Patricia Morales
- notifications_required:
    - "19:52Z: James Chen — IR Commander"
    - "19:54Z: Robert Kim — Technical Lead"
    - "19:56Z: Patricia Morales — CISO, executive escalation"
- notification_status: >
    Planned notification times for this exercise;
    actual delivery is not independently evidenced.
- first_communication:
    audience: James Chen, IR Commander
    proposed_at: 2026-04-20T19:52:00Z
    status: Draft; sending not independently verified
    message: >
      IR-2026-0420-01 activated at SEV2. Main Site reports
      severe degradation on CS-WS-101 and SCHED-SVR-01,
      with suspicious WinHealthSvc installation alerts on
      CS-WS-104, CS-WS-107 and CS-WS-112. Possible file
      encryption remains unconfirmed. Request immediate
      incident coordination, clinical impact assessment,
      evidence preservation and containment planning.
      Escalate severity if high patient-safety impact,
      full clinical outage or broad compromise is confirmed.
