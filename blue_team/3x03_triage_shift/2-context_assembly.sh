#!/bin/bash
set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

QUEUE="$CATALOG_DIR/alerts/alert_queue.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"
IOCS="$ASSETS_DIR/ioc_context.json"

mkdir -p tickets

python3 - "$QUEUE" "$ASSETS" "$EVENTS" "$BASELINE" "$IOCS" <<'PY'
import json
import sys

queue_file, assets_file, events_file, baseline_file, ioc_file = sys.argv[1:]

with open(queue_file, encoding="utf-8") as f:
    alerts = json.load(f)

with open(assets_file, encoding="utf-8") as f:
    data = json.load(f)

assets = {
    a.get("hostname"): a
    for a in data.get("assets", [])
    if a.get("hostname")
}

with open(baseline_file, encoding="utf-8") as f:
    baseline = json.load(f)

with open(ioc_file, encoding="utf-8") as f:
    iocs = json.load(f)

if isinstance(iocs, dict):
    ioc_map = iocs
else:
    ioc_map = {}
    for item in iocs:
        key = item.get("ip") or item.get("domain")
        if key:
            ioc_map[key] = item

needed = {
    str(a.get("event_ref"))
    for a in alerts
    if a.get("event_ref") is not None
}

events = {}
with open(events_file, encoding="utf-8") as f:
    for number, line in enumerate(f, 1):
        ref = str(number)
        if ref in needed:
            try:
                events[ref] = json.loads(line)
            except json.JSONDecodeError:
                pass
        if len(events) == len(needed):
            break

def profile(host):
    result = {}
    for section in baseline.values():
        if isinstance(section, dict) and host in section:
            result.update(section[host])
    return result

def band(score):
    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"

output = []
assets_joined = 0
missing_assets = 0
baseline_joined = 0
ioc_counts = {"malicious": 0, "suspicious": 0, "unknown": 0}

for alert in alerts:
    event = events.get(str(alert.get("event_ref")), {})
    summary = alert.get("event_summary", {})
    host = summary.get("hostname") or event.get("hostname") or ""

    asset = assets.get(host, {})
    if asset:
        assets_joined += 1
    else:
        missing_assets += 1

    base = profile(host)
    if base:
        baseline_joined += 1

    values = {
        summary.get("src_ip"),
        summary.get("dst_ip"),
        event.get("src_ip"),
        event.get("dst_ip"),
        summary.get("domain"),
        event.get("domain")
    }

    hits = []
    for value in values:
        if value and value in ioc_map:
            hit = dict(ioc_map[value])
            reputation = hit.get("reputation", "unknown")
            if reputation != "clean":
                hit["ioc_flag"] = True
                if reputation in ioc_counts:
                    ioc_counts[reputation] += 1
            hits.append(hit)

    item = dict(alert)
    item["asset"] = asset
    item["baseline_host_profile"] = base
    item["event_record"] = event
    item["ioc_hits"] = hits
    item["priority_band"] = band(
        float(alert.get("priority_score", 0))
    )
    output.append(item)

with open("enriched_queue.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)
    f.write("\n")

print(f"alerts processed          : {len(alerts)}")
print(f"assets joined             : {assets_joined}")
print(f"missing asset records     : {missing_assets}")
print(f"alerts with IOC hits      : {sum(ioc_counts.values())}")
print(f"  malicious               : {ioc_counts['malicious']}")
print(f"  suspicious              : {ioc_counts['suspicious']}")
print(f"  unknown                 : {ioc_counts['unknown']}")
print(f"baseline profiles joined  : {baseline_joined}")
print("enriched_queue.json written")
PY
