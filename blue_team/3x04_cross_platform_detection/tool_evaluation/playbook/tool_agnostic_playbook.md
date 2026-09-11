# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

This playbook defines a repeatable investigation workflow for MedDefense security events across CLI and SIEM interfaces. It enables Tier 1 analysts to reach evidence-based findings without depending on one vendor tool.

## Scope

Use this playbook for alert validation, event correlation, identity activity, process activity, network activity, and suspicious timelines. It covers normalized evidence investigated through CLI tools or exported SIEM/dashboard data. It does not replace incident response, malware analysis, forensic imaging, containment, eradication, or recovery procedures.

## Inputs

The analyst must have access to:

- Enriched events: `$HANDOFF_DIR/data/enriched_events.json`
- Asset inventory: `$HANDOFF_DIR/context/asset_inventory.json`
- Baseline package: `$BASELINE_PKG`
- Detection catalog: `$CATALOG_DIR`
- Triage package: `$TRIAGE_PKG`
- IOC context: `$ASSETS_DIR/3x03_assets/ioc_context.json`

If a required context field is absent from the primary artifact, use an approved available context source and record the fallback in the finding.

## Workflow Steps

| Step | CLI action | Export/dashboard action |
|---|---|---|
| 1. Define scope | Identify host, user, IP, alert, and investigation time window. | Set the dashboard time range and identify the alert or entity. |
| 2. Filter evidence | Use `jq` to select events matching the scoped entities and time window. | Apply KQL/Lucene filters for the same entities and time window. |
| 3. Build timeline | Sort matching events by timestamp and review their sequence. | Sort `@timestamp` ascending and inspect the ordered results. |
| 4. Inspect key fields | Read normalized identity, process, network, and raw-message fields. | Expand events and inspect mapped Wazuh fields and `full_log`. |
| 5. Add context | Join asset, baseline, detection, triage, and IOC context when relevant. | Use populated document fields first; perform a secondary lookup when context is missing. |
| 6. Test hypothesis | Compare event sequence, timing, behavior, and context against the suspected activity. | Pivot between related events and confirm or reject the same hypothesis. |
| 7. Map ATT&CK | Record only techniques supported by observed evidence. | Confirm dashboard mappings against the observed event evidence. |
| 8. Record finding | Write the locked finding fields and evidence references. | Record the same finding schema, including any dashboard or fallback actions. |

## Field Name Translation Table

| Normalized field | Wazuh field |
|---|---|
| `timestamp` | `@timestamp` |
| `hostname` | `agent.name` |
| `event_id` | `winlog.event_id` |
| `user` | `user.name` |
| `process_name` | `process.name` |
| `src_ip` | `source.ip` |
| `dst_ip` | `destination.ip` |
| `src_zone` | `source.zone` |
| `protocol` | `network.transport` |
| `raw_message` | `full_log` |

## Query Decomposition Rule

Every investigation query has three parts: **filter, aggregation, and time window**.

**Filter:** limit evidence to relevant hosts, users, event IDs, processes, IPs, or other entities. In `jq`, use `select(...)`; in Sigma, use `detection.selection` and `condition`; in KQL, use `field:value` expressions; in Lucene, use `field:value` clauses.

**Aggregation:** count, group, order, or correlate matching events. In `jq`, use arrays, `group_by`, `sort_by`, or `length`; in Sigma, use supported correlation or count conditions; in KQL, filter first and use dashboard aggregation controls; in Lucene, filter first and use the SIEM aggregation controls.

**Time window:** bound all evidence to the investigation period. In `jq`, compare parsed timestamps; in Sigma, define the applicable correlation timeframe; in KQL and Lucene workflows, set the dashboard time picker and retain the selected range with the investigation.

## Finding Schema

Every structured finding contains:

- `finding_id`: deterministic `scenario_id` plus interface
- `scenario_id`: `anchor`, `scenario_a`, `scenario_b`, or `scenario_c`
- `interface`: `cli` or `wazuh_export`
- `investigation_start`: ISO8601 UTC
- `investigation_end`: ISO8601 UTC
- `time_to_first_answer_seconds`: integer
- `actions`: ordered list, maximum 20
- `fields_touched`: list
- `event_refs`: evidence reference list
- `attack_techniques`: ATT&CK technique IDs
- `hypothesis`: maximum two sentences
- `confidence`: `low`, `medium`, or `high`
- `created_at`: ISO8601 UTC

## Exit Criteria

An investigation is complete when the scope and time window are bounded, relevant evidence has been reviewed, required context has been checked, the hypothesis is supported or rejected, ATT&CK mappings are evidence-based, and the finding contains the locked schema. Any missing field or fallback lookup must be documented before closure.

## Known Pitfalls

- A SIEM field may be absent even when the same value exists inside `full_log`.
- Asset classification may be missing from `agent.labels`, requiring an asset-inventory lookup.
- Dashboard summaries can describe trends that do not match the underlying event values, so verify claims against raw evidence.
- Export results can contain both firewall and IDS events, so distinguish event types before calculating beacon intervals.
- Normalized `event_id` values and Wazuh `winlog.event_id` values may use different JSON types, so filters must match the actual type.
