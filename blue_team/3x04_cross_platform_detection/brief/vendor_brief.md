# MedDefense Vendor Evaluation Brief

## Purpose

This brief evaluates the CLI and Wazuh export/dashboard interfaces using measured MedDefense investigation results. It recommends the primary analyst surface and defines when the secondary interface should be used.

## Evaluation Methodology

The evaluation used four investigation scenarios: the anchor investigation and Scenarios A, B, and C. Each scenario was completed through both CLI and Wazuh export workflows, producing eight findings with measured time to first answer, action count, fields touched, event references, and confidence.

The results were aggregated mechanically in `workflow_comparison.json` and compared per scenario in `tradeoff_table.json`. No vendor marketing or feature claims were used.

## Findings Summary

Across four CLI findings, total time to first answer was 63 seconds, with a 15.75-second average and 21-second median. CLI investigations required 19 total actions, touched 25 fields, and referenced 53 events.

Across four Wazuh export findings, total time was 3 seconds, with a 0.75-second average and 1-second median. Wazuh export investigations required 29 total actions, touched 22 fields, and referenced 69 events.

Both interfaces produced four high-confidence findings and no medium- or low-confidence findings. Wazuh export was faster in three of four scenarios; CLI was faster in Scenario C.

## Strengths and Weaknesses per Interface

The CLI required fewer actions in every scenario: 5 versus 7 for the anchor, 4 versus 7 for Scenario A, 5 versus 8 for Scenario B, and 5 versus 7 for Scenario C. Its strongest result was Scenario C, where pipeline expressiveness supported a direct beacon-interval investigation and produced the answer in 0 seconds versus 1 second for Wazuh export. The main weakness was slower time to first answer in the anchor and Scenarios A and B.

Wazuh export was faster for the anchor by 20 seconds, Scenario A by 21 seconds, and Scenario B by 20 seconds. Native field surfaces, timeline visualization, and filter-bar efficiency supported those advantages. Its main weakness was higher action count in every scenario and dependence on document field completeness; Scenario B required a fallback asset lookup because `data_classification` was absent from `agent.labels`.

## Recommendation

Use **Wazuh export/dashboard as the primary analyst interface** because it delivered the fastest measured answer in three of four scenarios and the lowest aggregate time to first answer.

Use **CLI as the secondary interface** when complex filtering, field validation, context joins, raw-data verification, or reproducible pipeline logic is required.

## Operational Risks of Being Wrong

* Choosing an interface that increases investigation steps could cost approximately **1–2 analyst hours per week** across repeated Tier 1 investigations.
* Relying only on dashboard fields when required context is absent could add approximately **1 analyst hour per week** in secondary lookups and revalidation.
* Relying only on CLI workflows for investigations where structured SIEM fields provide faster pivots could cost approximately **2–3 analyst hours per week** in additional investigation time.
* Failing to retain a secondary interface could cost approximately **1–2 analyst hours per week** when analysts must reconstruct missing context or manually validate raw evidence.

These estimates are operational planning estimates rather than measured findings and should be recalibrated with production case volume.

## Security+ 4.7 Considerations

Automation and structured SIEM fields improve efficiency and scaling, while CLI pipelines reduce complexity for repeatable filtering, validation, and context joins. Maintaining both paths has some cost and technical debt, but a primary Wazuh workflow with a bounded CLI fallback reduces operational risk without duplicating the full investigation process.

## Next Steps

1. Detection engineering: validate field mappings and ensure critical context such as asset classification is consistently populated.
2. Compliance: retain the findings, comparison datasets, playbook, and manifest as evaluation evidence.
3. SOC manager: adopt Wazuh as the primary Tier 1 surface and keep the CLI workflow available for fallback and advanced investigation.
4. SOC manager: repeat the measurement with production investigation volume and update the estimated weekly operational costs.
