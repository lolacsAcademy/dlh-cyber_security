# 0. Intelligence Intake

## Source 1 - HC3 Advisory

- Source name: HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
- Source type: government advisory
- Date: 2026-04-25
- TLP classification / distribution: TLP:CLEAR
- Indicators: 23
- Types: 8 domains, 6 IPs, 5 hashes, 4 URLs
- Claim: HEALTHBANE is a multi-stage campaign targeting US healthcare organizations.
- Limitation: Attribution is unconfirmed. HC3 has LOW confidence in attribution.

## Source 2 - Commercial Feed

- Source name: commercial_feed_extract.json
- Source type: commercial feed
- Date: 2026-04-26
- TLP classification / distribution: TLP:AMBER, internal MedDefense use only
- Indicators: 41
- Types: domains, IPs, hashes, URLs
- Claim: The feed links indicators to a campaign labelled VITALSCORE.
- Limitation: Not all indicators were human-reviewed. Some low-confidence indicators may be clustering noise.

## Source 3 - Researcher Blog

- Source name: researcher_blog_analysis.txt
- Source type: open-source research
- Date: 2026-04-24
- TLP classification / distribution: N/A, public blog post
- Indicators: 14
- Types: 5 domains, 3 IPs, 4 hashes, 2 URLs
- Claim: The researcher links the phishing kit and infrastructure to HEALTHBANE.
- Limitation: No victim telemetry. Attribution is MEDIUM confidence and based on tooling and infrastructure.

## Source 4 - MedDefense 4x00

- Source name: meddefens_4x00_findings.txt
- Source type: internal investigation
- Date: 2026-04-16
- TLP classification / distribution: TLP N/A; INTERNAL, not for external share
- Indicators: 11
- Types: 3 domains, 3 IPs, 1 hash, 1 URL, 3 email addresses
- Claim: Three phishing emails targeted MedDefense staff and one user likely submitted credentials.
- Limitation: Credential submission was LIKELY but not confirmed by packet evidence. No Stage 2 or Stage 3 activity was observed.

## Consolidated View

- Total raw indicators: 89
- Total unique indicators after deduplication: 64
- Multiple sources: Core HEALTHBANE domains, IPs, hashes and URLs appear in multiple sources.
- One source only: Some commercial-feed indicators, researcher artifacts and MedDefense email addresses appear in only one source.

## Source Conflicts

- Attribution: HC3 does not confirm a named actor. Acme uses VITALSCORE. The researcher uses APT-MEDAGENT with MEDIUM confidence.
- Confidence: Sources use different confidence levels based on their evidence.
- Commercial-feed noise: Some indicators are low confidence, shared infrastructure or similarity-based clustering.
- Missing indicators: Some single-source indicators are absent from stronger sources.
- Assessment: Single-source and low-confidence indicators need further validation.
