# 6. Kill Chain Reconstruction

## Timeline

- 2026-04-14: Earliest known HEALTHBANE phishing activity observed by an HC3 partner.
- 2026-04-14: MedDefense received phishing activity. A MedDefense user clicked a phishing link and likely submitted credentials.
- 2026-04-14 to 2026-04-16: Primary Stage 1 credential-harvesting window.
- 2026-04-16 to 2026-04-22: Stage 2 malware-delivery window.
- 2026-04-18: Researcher received a HEALTHBANE phishing email from a Midwest hospital contact.
- Around 2026-04-22: Researcher reports the exposed phishing kit was taken down.
- 2026-04-23 to 2026-04-26: Stage 3 data-exfiltration window.
- 2026-04-25: HC3 advisory published.
- 2026-04-26: Most recent activity reported in the HC3 Stage 3 window.

## Stage 1 - Credential Harvesting

### Phishing Operation

HEALTHBANE used spear-phishing emails from healthcare-themed lookalike domains. The emails impersonated staff portals, insurance services and HR benefits. Landing pages collected usernames and passwords through HTML forms.

### Targeting Pattern

HC3 reports at least 14 targeted US healthcare organizations, with direct or partner visibility on 6. Targets included hospital systems, outpatient clinics, medical billing services and regional insurance administrators.

Stage 1 was observed at all 6 HC3-visible organizations.

### Infrastructure

Known infrastructure includes:

- meddefense-portal.com
- medequip-supplies.net
- meddefense-benefits.org
- outlook-protection.com
- portal-secure-meddefense.com
- 91.234.99.107
- 185.176.43.22
- 164.90.218.73
- 51.38.42.17

The researcher recovered a PHP credential-harvesting kit using PHPMailer 6.6.0. The kit stored submitted credentials and forwarded them to attacker-controlled infrastructure.

### Known Victims and MedDefense Evidence

MedDefense investigated three phishing emails sent to employees. One user clicked the phishing link and reported entering a password. The investigation assessed credential submission as LIKELY, but packet evidence had not confirmed it at the close of 4x00.

### Success Rate

FACT: Stage 1 was observed at 6 of 6 HC3-visible organizations: 100%.

FACT: The campaign progressed through all three stages at 2 of those 6 organizations.

The available sources do not provide a complete credential-harvesting success rate across all 14 targeted organizations.

## Stage 2 - Malware Delivery

Stage 2 was observed at 2 of 6 HC3-visible organizations, or 33%, between 2026-04-16 and 2026-04-22.

Stolen Stage 1 credentials were used to authenticate to cloud email accounts. The attacker then sent follow-up emails from compromised accounts to colleagues.

The follow-up attachment was:

`HEALTHBANE_S2_invoice.docm`

Its macro downloaded:

`svchost_update.exe`

Known Stage 2 artifacts also include:

`sync_healthdata.ps1`

The executable was downloaded from HEALTHBANE secondary infrastructure, including `healthbane-c2.net`.

Persistence was established through:

- Scheduled task: `HealthSync Update Service`
- Registry Run key

The researcher independently identified Stage 1 infrastructure linked to `healthbane-c2.net` through the recovered phishing-kit configuration.

Evidence source: HC3 provides direct evidence for Stage 2 at visible victim organizations. The researcher provides supporting technical infrastructure evidence.

## Stage 3 - Data Exfiltration

Stage 3 was observed at 2 of 6 HC3-visible organizations between 2026-04-23 and 2026-04-26.

### Data Targeted

- Patient records
- Insurance claims data

### Method

The Stage 2 RAT encoded data into base32 subdomain labels and transmitted it using DNS TXT-record queries.

Observed characteristics:

- Destination: `data-sync.healthbane-c2.net`
- Query interval: 10-15 seconds
- Encoded label length: 44-60 characters
- C2 responses: TXT records containing base64-encoded commands

The researcher also recovered a configuration reference to:

`https://healthbane-c2.net/api/ingest`

### Evidence

FACT: HC3 directly observed DNS-based exfiltration in two compromised environments.

CORROBORATION: Researcher evidence connects the credential-harvesting kit to HEALTHBANE C2 infrastructure.

UNKNOWN: The sources do not establish the full quantity of data exfiltrated or complete Stage 3 visibility across every targeted organization.

## Evidence Quality Assessment

| Phase | Confirmed Evidence | Corroborated Evidence | Inferred Evidence | Unknowns |
|---|---|---|---|---|
| Stage 1 | Phishing, lookalike domains and credential forms observed | HC3, researcher and MedDefense overlap on infrastructure | Broader campaign activity beyond visible organizations | Full credential compromise rate |
| Stage 2 | Macro document, executable and persistence observed by HC3 | Researcher links Stage 1 kit to C2 infrastructure | Use of stolen credentials across additional victims | Stage 2 activity outside visible organizations |
| Stage 3 | DNS tunneling and targeted healthcare data observed by HC3 | Researcher identifies related C2/exfiltration configuration | Possible activity at organizations without telemetry | Full data volume and total affected victims |

## What Is Not Known

### Attribution

HC3 does not confirm attribution to a named actor. The commercial feed uses `VITALSCORE`. The researcher uses `APT-MEDAGENT` with MEDIUM confidence. MedDefense 4x00 avoids actor attribution.

These labels should not be treated as confirmed equivalents.

### Missing Victim Telemetry

HC3 has direct or partner visibility on only 6 of at least 14 targeted organizations. The researcher explicitly lacks victim telemetry. Therefore, the complete campaign impact cannot be confirmed.

### Incomplete Stage 3 Visibility

Stage 3 is confirmed at two HC3-visible organizations. The sources do not establish whether exfiltration occurred at additional victims or the total volume of stolen data.

### Commercial-Feed Uncertainty

The commercial feed provides useful indicator enrichment but contains shared infrastructure, low-confidence indicators and weak ML similarity clustering. These indicators require corroboration before operational use.

### Collection Needed

The main intelligence gaps could be reduced by collecting:

- Authentication logs following Stage 1 credential submission
- Cloud email audit logs for compromised accounts
- Endpoint telemetry for `.docm`, PowerShell and persistence activity
- DNS logs showing long encoded TXT queries
- Network telemetry covering Stage 2 and Stage 3
- Additional victim telemetry from healthcare-sector partners

## Assessment

FACT: HEALTHBANE is confirmed as a multi-stage healthcare campaign progressing from credential harvesting to malware delivery and DNS-based data exfiltration at two HC3-visible organizations.

ASSESSMENT: Stage 1 has the broadest evidence and visibility. Stage 2 and Stage 3 are confirmed but observed in fewer environments. Attribution remains unresolved and should not be overstated.

Confidence: HIGH for the three-stage campaign sequence; LOW for named-actor attribution.
