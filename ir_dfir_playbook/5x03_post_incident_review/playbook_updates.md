
# IR Playbook Updates: IR-2026-0414-01

**Source playbook:** `playbook_credential_exposure.yaml`

## Change PB-UPD-001 — VPN Impossible-Travel Trigger

**Playbook:** playbook_credential_exposure.yaml  
**Section:** applies_to.triggers  
**Gap closed:** GAP-003, GAP-004  
**Finding reference:** Forensic summary — foreign-IP authentication from 45.63.9.88 and suppressed Azure AD risk signals.

**Before:**
```yaml
triggers:
  - Successful Azure AD sign-in from an unfamiliar foreign IP
```

**After:**
```yaml
triggers:
  - Successful Azure AD sign-in from an unfamiliar foreign IP
  - VPN authentication from a country not seen for the account in 30 days
  - Impossible-travel alert involving geographically inconsistent
    account sign-ins within two hours
```

**Reason:** The existing trigger covered unfamiliar Azure AD sign-ins but did not explicitly identify VPN impossible-travel. The incident involved suspicious foreign-origin authentication requiring investigation.

---

## Change PB-UPD-002 — Lateral Movement Scope Expansion

**Playbook:** playbook_credential_exposure.yaml  
**Section:** containment_actions  
**Gap closed:** GAP-010  
**Finding reference:** ART-003-M01, AD-LOG-01.

**Before:**
```yaml
containment_actions:
  - step: Reset the compromised Active Directory password
  - step: Revoke active VPN tokens associated with the account
```

**After:**
```yaml
containment_actions:
  - step: Expand incident scope when lateral movement is detected
    owner: Technical_Lead
    checklist:
      - Identify source and destination hosts
      - Correlate Kerberos logons and suspicious ticket use
      - Identify additional affected accounts and sessions
      - Preserve logs and memory evidence from newly identified hosts
      - Add confirmed affected hosts to the incident inventory
      - Isolate affected hosts after clinical impact assessment
      - Revoke compromised sessions and credentials
      - Review access to ePHI systems and shared resources
    decision_point: IR Commander approves expanded containment
```

**Reason:** ART-003-M01 confirmed activity on WST-WS-017 following a Kerberos logon from WST-WS-031. AD-LOG-01 confirmed access to 14 patient reports. Containment must expand beyond the initially identified workstation.

---

## Change PB-UPD-003 — Kerberos Ticket Recovery

**Playbook:** playbook_credential_exposure.yaml  
**Section:** eradication_actions  
**Gap closed:** GAP-008, GAP-010  
**Finding reference:** ART-002-M04, ART-003-M01.

**Before:**
```yaml
containment_actions:
  - step: Reset the compromised Active Directory password
```

**After:**
```yaml
eradication_actions:
  - Investigate suspected Pass-the-Ticket activity
  - Identify affected accounts, hosts, and Kerberos sessions
  - Revoke affected sessions and reset compromised credentials
  - Determine whether forged Kerberos tickets or krbtgt
    compromise are suspected or confirmed
  - If krbtgt compromise or forged TGTs are established,
    coordinate two krbtgt password resets with AD specialists
  - Complete the resets using the documented AD recovery
    procedure and required replication and timing checks
  - Validate Kerberos authentication and monitor for renewed abuse
```

**Reason:** The incident demonstrated Kerberos-related lateral movement and credential exposure. Account password resets alone may not invalidate all stolen tickets. However, Pass-the-Ticket does not itself prove `krbtgt` compromise. Double-reset must follow confirmation of the relevant threat and an approved Active Directory recovery procedure.

---

## Change PB-UPD-004 — HIPAA Four-Factor Decision Node

**Playbook:** playbook_credential_exposure.yaml  
**Section:** escalation_triggers / containment_actions  
**Gap closed:** GAP-010  
**Finding reference:** AD-LOG-01 — 14 patient laboratory reports accessed.

**Before:**
```yaml
escalation_triggers:
  - Determine whether ePHI was accessible to the compromised
    account during the exposure window
  - Notify Legal Liaison for HIPAA breach assessment
    if ePHI access was possible
```

**After:**
```yaml
containment_actions:
  - step: Perform HIPAA four-factor breach risk assessment
    owner: Legal_Liaison
    trigger: Confirmed or suspected unauthorized access to ePHI
    checklist:
      - Identify the nature and extent of ePHI involved
      - Identify the unauthorized person who accessed or received it
      - Determine whether ePHI was actually acquired or viewed
      - Evaluate the extent to which risk was mitigated
    decision_point: >
      Legal Liaison documents whether there is a low probability
      that ePHI was compromised and determines applicable
      notification obligations.
```

**Reason:** AD-LOG-01 confirmed access to 14 laboratory report PDFs containing ePHI. External exfiltration was not confirmed, but the absence of confirmed exfiltration does not eliminate the need for a documented HIPAA breach risk assessment.

---

## Implementation Note

These entries document proposed changes to the existing credential exposure playbook. They do not modify `playbook_credential_exposure.yaml` directly.

All four updates require review by the IR Commander and relevant technical or legal owners before operational deployment.
