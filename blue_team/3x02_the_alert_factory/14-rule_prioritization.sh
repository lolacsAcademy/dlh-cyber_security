#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RISK="$ASSETS_DIR/risk_register.json"
QUALITY="rule_quality.json"
COVERAGE="attack_coverage.json"
OUTPUT="rule_prioritization.json"

python3 - "$RISK" "$QUALITY" "$COVERAGE" "$OUTPUT" <<'PY'
import json
import sys
import glob
import os
import yaml

risk_file, quality_file, coverage_file, output = sys.argv[1:]

with open(risk_file, encoding="utf-8") as f:
    risk = json.load(f)

with open(quality_file, encoding="utf-8") as f:
    quality = json.load(f)

with open(coverage_file, encoding="utf-8") as f:
    coverage = json.load(f)

rule_names = {}

for path in glob.glob("rules/sigma/*.yml"):
    with open(path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    rule_names[rule["id"]] = os.path.basename(path)

rule_map = coverage.get("rule_to_technique_map", {})

likelihood_score = {
    "high": 6,
    "medium": 4,
    "low": 2
}

impact_score = {
    "critical": 3,
    "high": 2,
    "medium": 1
}

results = []

for rule in quality:
    rule_id = rule["rule_id"]
    filename = rule_names.get(rule_id, "")
    techniques = {
        x.upper()
        for x in rule_map.get(filename.replace(".yml", ""), [])
    }

    risk_score = 0
    scenarios = []

    for scenario in risk.get("scenarios", []):
        scenario_techniques = {
            x.upper()
            for x in scenario.get("mitre_techniques", [])
        }

        if techniques & scenario_techniques:
            likelihood = likelihood_score.get(
                str(scenario.get("likelihood", "")).lower(), 0
            )
            impact = impact_score.get(
                str(scenario.get("impact", "")).lower(), 0
            )

            risk_score += likelihood * impact
            scenarios.append(scenario["scenario_id"])

    f1 = float(rule.get("f1", 0))
    priority = risk_score * f1

    if f1 == 0:
        priority = risk_score * 0.1

    results.append({
        "rule_id": rule_id,
        "rule_title": rule["rule_title"],
        "risk_score": risk_score,
        "f1": f1,
        "priority_score": round(priority, 4),
        "covering_scenarios": scenarios,
        "level": rule["level"]
    })

results.sort(key=lambda x: x["priority_score"], reverse=True)

with open(output, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
    f.write("\n")

print("top 10 rules by priority_score")

for number, item in enumerate(results[:10], 1):
    print(
        f'{number:2d}  {item["priority_score"]:5.1f}  '
        f'{item["rule_title"]}'
    )

orphans = [
    item for item in results
    if item["priority_score"] == 0
]

print(
    f"orphan rules (no risk scenario covers) : {len(orphans)}"
)
print("rule_prioritization.json written")
PY
