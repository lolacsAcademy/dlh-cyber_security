# 0. Intelligence Intake

## Source 1 - HC3 Advisory

- Source name: HC3 HEALTHBANE Sector Threat Advisory
- Source type: government advisory
- Date: 2026-04-25
- Distribution: TLP:CLEAR
- Indicators: 23
- Types: 8 domains, 6 IPs, 5 hashes, 4 URLs
- Claim: HEALTHBANE is a multi-stage campaign targeting US healthcare organizations.
- Limitation: Attribution is unconfirmed. HC3 has LOW confidence in attribution.

## Source 2 - Acme Commercial Feed

- Source name: Acme CTI Commercial Feed
- Source type: commercial feed
- Date: 2026-04-26
- Distribution: TLP:AMBER, internal MedDefense use
- Indicators: 41
- Types: domains, IPs, hashes, URLs
- Claim: The feed links indicators to a campaign labelled VITALSCORE.
- Limitation: Not all indicators were human-reviewed. Several low-confidence items may be clustering noise.

## Source 3 - Researcher Blog

- Source name: The Phishing Kit Behind The HEALTHBANE Campaign
- Source type: open-source research
- Date: 2026-04-24
- Distribution: Public, no TLP marking
- Indicators: 14
- Types: 5 domains, 3 IPs, 4 hashes, 2 URLs
- Claim: The researcher links the phishing kit and infrastructure to HEALTHBANE.
- Limitation: The researcher has no victim telemetry. Attribution is MEDIUM confidence and based on tooling and infrastructure.

## Source 4 - MedDefense 4x00

- Source name: MedDefense 4x00 Internal Investigation Summary
- Source type: internal investigation
- Date: 2026-04-16
- Distribution: INTERNAL
- Indicators: 11
- Types: 3 domains, 3 IPs, 1 hash, 1 URL, 3 email addresses
- Claim: Three phishing emails targeted MedDefense staff and likely exposed one user's credentials.
- Limitation: Credential submission was LIKELY but not confirmed by packet evidence. No Stage 2 or Stage 3 activity was observed.

## Consolidated View

- Total raw indicators: 89
- Total unique indicators after deduplication: 64
- Multiple sources: core HEALTHBANE domains, IPs, hashes and URLs are reported by more than one source.
- One source only: several commercial-feed indicators, researcher-specific artifacts and the MedDefense email addresses occur in only one source.

## Source Conflicts

- Attribution: HC3 does not confirm a named actor. Acme uses VITALSCORE. The researcher uses APT-MEDAGENT with MEDIUM confidence.
- Confidence: Sources assign different confidence levels because they use different evidence.
- Commercial-feed noise: Several indicators are low confidence, shared infrastructure or similarity-based clustering.
- Missing indicators: Some indicators appear in only one source and are absent from stronger sources.
- Assessment: Single-source and low-confidence indicators require validation before defensive use.
