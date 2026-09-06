# MedDefense SOC Triage Methodology

## Classification Taxonomy

**true_positive** — Evidence confirms malicious or unauthorized activity. Example: `001_ssh_brute_force` with repeated `login_failure` events from the same `src_ip`.

**false_positive** — The alert matches the rule, but evidence shows the activity is not a security incident. Example: `002_windows_offhours_privileged_logon` caused by an authorized administrator.

**benign** — The activity is expected and authorized with no security concern. Example: an approved off-hours privileged logon.

**escalated** — Evidence indicates material risk or insufficient evidence for safe closure and requires Tier 2 investigation. Example: `003_interpreter_abuse` with suspicious process activity.

## Priority Ordering Rule

Work alerts in descending `priority_score`. For equal scores, work the oldest alert first. Override normal ordering for active compromise, confirmed malicious IOC activity, multiple affected hosts, or other immediate high-risk conditions.

## Evidence Requirement

**true_positive:** `event_ref`, `event_summary`, `event_category`, and relevant fields such as `process_name`, `src_ip`, or `dst_ip`.

**false_positive:** `event_ref` plus the specific field and value showing authorized or expected activity.

**benign:** `event_ref` plus fields such as `user`, `process_name`, `event_category`, or asset context showing expected activity.

**escalated:** `event_ref` plus the specific unresolved or high-risk field and value requiring Tier 2 review.

## Escalation Criteria

* `priority_score >= 20`
* confirmed malicious IOC
* multiple affected hosts
* insufficient evidence for safe classification
* active compromise or privileged abuse

## SLA

**critical:** 15 minutes
**high:** 30 minutes
**medium:** 60 minutes
**low:** same day

## Documentation Standard

* [ ] `ticket_id`
* [ ] `alert_id`
* [ ] `classification`
* [ ] `justification`
* [ ] `evidence_refs`
* [ ] `ioc_hits`
* [ ] `attack_techniques`
* [ ] `recommended_action`
* [ ] `analyst_time_seconds`
* [ ] `created_at`
