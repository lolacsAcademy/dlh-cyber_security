# 2. Source Credibility Matrix

## Assessment Methodology

This assessment uses the Admiralty Code adapted for cyber intelligence.

- Source reliability: A = completely reliable, B = usually reliable, C = fairly reliable, D = not usually reliable, E = unreliable, F = cannot be judged.
- Information credibility: 1 = confirmed, 2 = probably true, 3 = possibly true, 4 = doubtful, 5 = improbable, 6 = cannot be judged.
- Confidence: HIGH, MEDIUM or LOW based on source reliability, evidence and corroboration.

## Source Assessments

### HC3 Advisory

- Source reliability: A
- Information credibility: 2
- Confidence: HIGH for sector facts; LOW for actor attribution.
- Timeliness: Published 2026-04-25 and covers activity through 2026-04-22.
- Relevance: HIGH. It focuses directly on US healthcare organizations and includes MedDefense-contributed indicators.
- Limitations: HC3 does not confirm attribution to a named threat actor.
- Bias / visibility: Strong healthcare-sector visibility, but reporting depends on information submitted by participating organizations.

### Commercial Feed

- Source reliability: B
- Information credibility: 3
- Confidence: MEDIUM overall.
- Timeliness: Published 2026-04-26, making it the newest of the four sources.
- Relevance: HIGH for indicator enrichment and infrastructure correlation.
- Limitations: Not all indicators were human-reviewed. The feed includes low-confidence indicators, shared infrastructure and similarity-based clustering.
- Bias / visibility: Automated clustering can introduce noise. The VITALSCORE attribution should not be treated as confirmed.

### Researcher Blog

- Source reliability: C
- Information credibility: 3
- Confidence: MEDIUM.
- Timeliness: Published 2026-04-24.
- Relevance: HIGH for phishing-kit, infrastructure and technical analysis.
- Limitations: The researcher has no victim telemetry and cannot independently confirm campaign scope.
- Bias / visibility: Analysis is based mainly on tooling and infrastructure. Attribution to APT-MEDAGENT is explicitly MEDIUM confidence.

### MedDefense 4x00

- Source reliability: A
- Information credibility: 1
- Confidence: HIGH for directly observed MedDefense activity.
- Timeliness: Report dated 2026-04-16 and covers the internal investigation from 2026-04-14 to 2026-04-16.
- Relevance: VERY HIGH for MedDefense because it contains direct internal evidence.
- Limitations: Credential submission was assessed as LIKELY but was not confirmed by packet evidence at the close of 4x00. Stage 2 and Stage 3 activity was not observed.
- Bias / visibility: Visibility is strong inside MedDefense but limited to the organization's own environment and investigation window.

## Source Comparison Matrix

| Source | Reliability | Credibility | Confidence | Timeliness | MedDefense Relevance | Main Limitation |
|---|---|---|---|---|---|---|
| HC3 Advisory | A | 2 | HIGH | 2026-04-25 | HIGH | Attribution unconfirmed |
| Commercial Feed | B | 3 | MEDIUM | 2026-04-26 | HIGH | Noise and weak clustering |
| Researcher Blog | C | 3 | MEDIUM | 2026-04-24 | HIGH | No victim telemetry |
| MedDefense 4x00 | A | 1 | HIGH | 2026-04-16 | VERY HIGH | Limited to internal visibility |

## Attribution Conflict

FACT: HC3 uses the campaign name HEALTHBANE and does not endorse VITALSCORE attribution.

FACT: The commercial feed associates the activity with VITALSCORE.

FACT: The researcher proposes APT-MEDAGENT with MEDIUM confidence.

FACT: MedDefense 4x00 avoids actor attribution and reports only observed campaign activity.

ASSESSMENT: The evidence does not support a definitive actor attribution. HEALTHBANE should remain the operational campaign label. VITALSCORE and APT-MEDAGENT should be retained as unconfirmed attribution hypotheses.

Confidence: HIGH.

## Weighting Recommendation

- Prioritize HC3 for confirmed healthcare-sector facts because it provides authoritative sector-level reporting.
- Prioritize MedDefense 4x00 for facts directly observed in the MedDefense environment.
- Use the researcher blog for technical details about tooling, infrastructure and phishing-kit behavior, while preserving its stated uncertainty.
- Treat the commercial feed carefully where indicators depend on shared infrastructure, low confidence or weak similarity clustering.
- Do not resolve conflicting attribution claims by choosing the most specific actor name. Preserve the conflict, compare corroborating evidence and assign confidence explicitly.
