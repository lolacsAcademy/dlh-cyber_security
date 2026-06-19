# Task 1: Healthcare Mobile App Threat Model

## System Overview

Patients use a mobile app to view medical records, schedule appointments, message healthcare providers, and request prescription refills.

Architecture:
- Mobile client (iOS/Android)
- REST API backend
- Cloud-hosted database
- Integration with hospital systems

## System Architecture
+------------------+

|  Mobile Client    |

|  (iOS/Android)    |

+--------+----------+

|

| HTTPS

|

+--------v----------+

|   REST API         |

|   Backend          |

+--------+----------+

|

+----+----+

|         |

+---v---+ +---v------------+

| Cloud  | | Hospital        |

| DB     | | Systems         |

+--------+ +-----------------+

## 1. Most Critical Asset

The most critical asset is the **patient medical record (Protected Health Information / PHI)** stored and accessed through this app.

Looking at it through the CIA Triad:

**Confidentiality** - Medical records contain extremely sensitive personal data (diagnoses, prescriptions, mental health info, etc.). Under HIPAA, this data must stay confidential, and a breach can mean huge fines and loss of patient trust.

**Integrity** - If a record is changed by mistake or by an attacker (wrong medication, wrong allergy info), it can directly harm a patient's health. Medical data has to stay accurate.

**Availability** - Doctors and patients need access to records when needed, especially in emergencies. But compared to confidentiality and integrity, availability is usually treated as slightly less critical for compliance purposes, since a temporary outage is less damaging than a wrong or leaked record.

Because of this, confidentiality and integrity of PHI are the top priorities, which is why medical records are the most critical asset in this system.

## 2. STRIDE for "Message Healthcare Providers" Feature

### Threat 1: Spoofing - Impersonating a Provider

**STRIDE Category:** Spoofing (S)

**Threat Description**
An attacker could pretend to be a doctor or healthcare provider and send messages to a patient, for example by stealing provider credentials or exploiting weak authentication.

**Attack Scenario**
1. Attacker obtains a provider's login credentials through phishing.
2. Attacker logs into the provider's messaging account.
3. Attacker sends a message to a patient pretending to be their doctor.

**Potential Impact**
- Patient receives false medical advice
- Trust in the platform is damaged
- Possible harm if patient acts on fake instructions

**Likelihood:** Medium - depends on how strong provider authentication is.

**Suggested Mitigation**
Require multi-factor authentication (MFA) for all provider accounts, and clearly verify provider identity in the app UI.

### Threat 2: Tampering - Message Modification

**STRIDE Category:** Tampering (T)

**Threat Description**
A message between a patient and provider could be intercepted and changed in transit, for example altering medication instructions.

**Attack Scenario**
1. Attacker intercepts network traffic between the app and the API (e.g. on unsecured Wi-Fi).
2. Attacker modifies the content of a message before it reaches the recipient.
3. Patient or provider acts on the altered message.

**Potential Impact**
- Wrong medical instructions followed
- Possible patient harm
- Loss of trust in the system

**Likelihood:** Low-Medium - requires intercepting traffic, harder if TLS is properly enforced.

**Suggested Mitigation**
Use end-to-end encryption for messages and enforce TLS for all API traffic so messages can't be read or changed in transit.

### Threat 3: Repudiation - Denying a Message Was Sent

**STRIDE Category:** Repudiation (R)

**Threat Description**
A provider (or patient) could deny having sent a specific message, for example denying they gave certain medical advice, if there's no reliable record of who sent what and when.

**Attack Scenario**
1. A provider sends instructions through the messaging feature.
2. Later, a dispute arises (e.g. a complaint or legal issue).
3. The provider denies sending the message, and there's no solid log to prove otherwise.

**Potential Impact**
- Disputes can't be resolved
- Legal/compliance risk
- Accountability is lost

**Likelihood:** Medium - common issue if logging isn't built in from the start.

**Suggested Mitigation**
Keep detailed, tamper-proof audit logs of all messages, including sender, timestamp, and message content, so actions can always be traced back.

### Threat 4: Information Disclosure - Message Content Exposure

**STRIDE Category:** Information Disclosure (I)

**Threat Description**
Messages between patients and providers often contain sensitive health details. If messages aren't properly protected (in storage or transit), they could be exposed to unauthorized people.

**Attack Scenario**
1. Messages are stored in the cloud database without encryption.
2. Database is breached or accessed by someone without proper authorization.
3. Sensitive patient-provider conversations are exposed.

**Potential Impact**
- HIPAA violation
- Patient privacy breach
- Reputational and legal damage

**Likelihood:** Medium - depends on how well the database and access controls are configured.

**Suggested Mitigation**
Encrypt messages both at rest and in transit, and restrict database access to only the services that need it.

## 3. Priority Security Controls for Patient Data

1. **Authentication** - This comes first because if you can't verify who's accessing the data, nothing else matters. Strong authentication (including MFA for providers) is the front door to everything else.

2. **Encryption** - Patient data must be encrypted both at rest (in the database) and in transit (between app, API, and hospital systems), so even if data is intercepted or a database is breached, it can't be read.

3. **Access Controls** - Once someone is authenticated, they should only be able to see the data relevant to their role (a patient sees their own records, a provider sees their patients' records, not everyone sees everything). This limits damage if one account is compromised.

4. **Audit Logging** - Keeping logs of who accessed what data and when supports accountability, helps detect suspicious activity, and is often required for HIPAA compliance.

5. **Regular Security Testing** - Periodically testing the app and API (vulnerability scanning, penetration testing) helps catch new weaknesses before attackers find them, especially important since the app integrates with external hospital systems.

## References
- HIPAA Security Rule (U.S. Department of Health and Human Services).
- OWASP Cheat Sheet Series - Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
