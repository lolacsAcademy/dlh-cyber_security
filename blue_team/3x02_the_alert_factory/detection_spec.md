# MedDefense Detection Engineering Specification

## Purpose

The MedDefense detection layer converts normalized security telemetry into consistent, risk-ranked alerts for SOC triage. It defines how Sigma rules are authored, executed, measured, tuned, prioritized, and delivered to 3x03.

## Inputs

- `$HANDOFF_DIR/data/normalized_events.json` — normalized event evidence. `HANDOFF_DIR` defaults to `~/3x00_handoff/evidence_handoff`.
- `$HANDOFF_DIR/context/asset_inventory.json` — asset and criticality context.
- `$BASELINE_PKG/baselines/baseline_summary.json` — baseline and evaluation windows. `BASELINE_PKG` defaults to `~/3x01_package/baseline_package`.
- `$BASELINE_PKG/anomalies/ranked_anomalies.json` — ranked anomaly evidence.
- `$BASELINE_PKG/taxonomy/labeled_events.json` — labeled events used for quality measurement.
- `$ASSETS_DIR/risk_register.json` — threat scenarios, likelihood, impact, and ATT&CK techniques. `ASSETS_DIR` defaults to `~/3x02_assets`.
- `attack_coverage.json` — mapping between catalog rules and ATT&CK techniques.
- `rule_prioritization.json` — calculated rule risk priorities.

## Rule Authoring Standard

Rules use Sigma-compatible YAML and reside under `rules/sigma/`; tuned variants reside under `rules/sigma/tuned/`. Required fields are `title`, `id`, `status`, `description`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, and `tags`.

Rule filenames use a three-digit catalog number followed by a descriptive snake_case name, for example `001_ssh_brute_force.yml`. Each rule has a stable unique ID. Rules must include applicable MITRE ATT&CK technique tags using the `attack.tXXXX` or sub-technique form.

## Execution Model

`3-sigma_runner.sh` executes rules against `normalized_events.json`. It supports filtering, field matching, supported string operators, aggregation, derived fields, and rule conditions required by the catalog.

Execution is bounded by an explicit time window. Baseline execution measures expected activity during days 1–7; evaluation execution measures detections during day 8. Event references preserve traceability to the normalized source record.

## Quality Thresholds

Rules are assessed using true positives, false positives, and false negatives. Precision measures the proportion of alerts that are true positives; recall measures the proportion of known relevant events detected; F1 balances precision and recall.

A rule with F1 below `0.30` is marked `[WEAK]` and must not ship without review and tuning. F1 of `0.70` or greater is `[STRONG]`. Baseline false-positive rates above 10 alerts per day require tuning. Precision and recall must also be reviewed to ensure a high F1 does not hide unacceptable missed detections or alert noise.

## Tuning Protocol

A noisy rule is first executed against the baseline window to identify expected activity causing false positives. The engineer adds the narrowest justified exclusion or condition and stores the tuned variant under `rules/sigma/tuned/`, preserving the original rule.

The tuned rule is rerun against both baseline and evaluation windows. Tuning is accepted only when false positives decrease without unacceptable loss of true-positive coverage, and the resulting precision, recall, and F1 are recalculated.

## Risk Ranking Model

Rule priority combines detection quality with business risk. A rule's `risk_score` is the sum of `likelihood × impact` for risk-register scenarios whose ATT&CK techniques intersect techniques covered by that rule.

`priority_score = risk_score × F1`. When F1 is zero, a floor of `risk_score × 0.1` preserves visibility for risk-relevant rules that lack measured quality. Rules with no covered risk scenario are reported as orphans.

## Outputs

`alert_queue.json` is the production interface to 3x03 Triage Shift. Each alert contains `alert_id`, `generated_at`, rule identity and level, `priority_score`, `event_ref`, flattened `event_summary`, `asset_context`, ATT&CK techniques, `status`, and `evidence_hash`.

Alerts are deduplicated within 60 seconds on `(rule_id, hostname, user)` and ranked by descending priority score, with timestamp ascending as the tie-breaker. `alert_queue_schema.json` defines the field-level contract. 3x03 must be able to consume the queue without changing its schema.

## Failure Modes

- **Missing or malformed input:** scripts fail, produce parsing errors, or generate incomplete outputs.
- **Incorrect execution window:** baseline activity may appear malicious or evaluation detections may be omitted.
- **Rule/schema mismatch:** valid telemetry produces no matches because rule fields do not align with normalized fields.
- **Excessive false positives:** baseline counts exceed the tuning threshold and overwhelm triage.
- **Broken event references:** alerts cannot be traced back to their source evidence.
- **Incorrect ATT&CK mapping:** risk scores and catalog coverage become misleading.

## Reviewer Checklist

- Confirm required Sigma fields and unique stable rule ID.
- Confirm filename and catalog naming convention.
- Confirm logsource and detection fields match normalized telemetry.
- Confirm ATT&CK technique tags are valid and justified.
- Run the rule against baseline and evaluation windows.
- Review false-positive rate, precision, recall, and F1.
- Tune noisy rules and verify true-positive coverage remains acceptable.
- Confirm event references resolve to normalized evidence.
- Confirm risk mapping and priority calculation.
- Confirm generated alerts conform to `alert_queue_schema.json`.
