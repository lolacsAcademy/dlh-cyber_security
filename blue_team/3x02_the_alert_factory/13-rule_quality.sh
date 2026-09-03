#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"
ANOMALIES="$BASELINE_PKG/anomalies/ranked_anomalies.json"
LABELED="$BASELINE_PKG/taxonomy/labeled_events.json"
FP="fp_baseline.json"
OUTPUT="rule_quality.json"

START=$(jq -r '.evaluation_window.start' "$SUMMARY")
END=$(jq -r '.evaluation_window.end' "$SUMMARY")

python3 - "$ANOMALIES" "$LABELED" "$FP" "$START" "$END" "$OUTPUT" <<'PY'
import json
import sys
import subprocess
import glob

anomaly_file, labeled_file, fp_file, start, end, output = sys.argv[1:]

with open(anomaly_file, encoding="utf-8") as f:
    anomalies = json.load(f)

truth = set()

with open(labeled_file, encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        event = json.loads(line)

        if not event.get("canonical_label") or event["canonical_label"] == "unlabeled":
            continue

        for anomaly in anomalies:
            if (
                event.get("timestamp") == anomaly.get("timestamp")
                and event.get("hostname") == anomaly.get("host")
                and event.get("process_name") == anomaly.get("process_name")
            ):
                truth.add(str(line_no))

with open(fp_file, encoding="utf-8") as f:
    fp_data = json.load(f)

fp_by_rule = {x["rule_id"]: x["fp_count"] for x in fp_data}
rules = sorted(glob.glob("rules/sigma/*.yml"))
results = []

for rule in rules:
    run = subprocess.run(
        ["./3-sigma_runner.sh", rule, "--window", f"{start},{end}"],
        capture_output=True,
        text=True,
        check=True
    )

    data = json.loads(run.stdout)
    refs = {str(x["event_ref"]) for x in data.get("matches", [])}

    tp = len(refs & truth)
    fp = len(refs - truth) + fp_by_rule.get(data["rule_id"], 0)
    fn = len(truth - refs)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    results.append({
        "rule_id": data["rule_id"],
        "rule_title": data["rule_title"],
        "level": data["level"],
        "tp_count": tp,
        "fp_count": fp,
        "fn_count": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4)
    })

with open(output, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
    f.write("\n")

ordered = sorted(results, key=lambda x: x["f1"], reverse=True)

print("strongest")
for x in ordered[:5]:
    mark = " [STRONG]" if x["f1"] >= 0.7 else ""
    print(
        f'  {x["rule_title"]}  f1={x["f1"]:.2f}  '
        f'p={x["precision"]:.2f} r={x["recall"]:.2f}{mark}'
    )

print("weakest")
for x in ordered[-5:]:
    mark = " [WEAK]" if x["f1"] < 0.3 else ""
    print(
        f'  {x["rule_title"]}  f1={x["f1"]:.2f}  '
        f'p={x["precision"]:.2f} r={x["recall"]:.2f}{mark}'
    )

print("rule_quality.json written")
PY
