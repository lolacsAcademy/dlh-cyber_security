#!/bin/bash
set -euo pipefail

python3 <<'PY'
import csv
import json
import os
from datetime import datetime, timezone

PACK = os.path.expanduser("~/evidence_pack_primary/network")
OUT = "network_events.json"
ALL = "normalized_events.json"
events = []

def iso(value):
    value = value.replace("Z", "+00:00")
    if value.endswith("+0000"):
        value = value[:-5] + "+00:00"
    d = datetime.fromisoformat(value)
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

with open(PACK + "/firewall.csv", encoding="utf-8") as f:
    count = 0
    for r in csv.DictReader(f):
        ts = datetime.fromtimestamp(
            float(r["timestamp"]), timezone.utc
        ).isoformat().replace("+00:00", "Z")
        events.append({
            "timestamp": ts,
            "hostname": None,
            "source_type": "firewall",
            "event_category": "network",
            "severity": None,
            "user": None,
            "process_name": None,
            "process_id": None,
            "src_ip": r["src_ip"],
            "src_port": int(r["src_port"]) if r["src_port"] else None,
            "dst_ip": r["dst_ip"],
            "dst_port": int(r["dst_port"]) if r["dst_port"] else None,
            "protocol": r["protocol"],
            "event_id": r["rule_id"],
            "provider": "firewall",
            "raw_message": json.dumps(r),
            "event_data": {
                "interface": r["interface"],
                "bytes_in": r["bytes_in"],
                "bytes_out": r["bytes_out"]
            },
            "source_origin": "evidence_pack",
            "action": r["action"]
        })
        count += 1
print(f"firewall.csv        : {count} records normalized")

with open(PACK + "/suricata_eve.json", encoding="utf-8") as f:
    count = 0
    for line in f:
        if not line.strip():
            continue
        r = json.loads(line)
        alert = r.get("alert", {})
        events.append({
            "timestamp": iso(r["timestamp"]),
            "hostname": r.get("host"),
            "source_type": "suricata",
            "event_category": "network_alert",
            "severity": alert.get("severity"),
            "user": None,
            "process_name": None,
            "process_id": None,
            "src_ip": r.get("src_ip"),
            "src_port": r.get("src_port"),
            "dst_ip": r.get("dest_ip"),
            "dst_port": r.get("dest_port"),
            "protocol": r.get("proto"),
            "event_id": str(r["flow_id"]) if r.get("flow_id") is not None else None,
            "provider": "suricata",
            "raw_message": line.rstrip(),
            "event_data": r,
            "source_origin": "evidence_pack",
            "signature": alert.get("signature")
        })
        count += 1
print(f"suricata_eve.json   : {count} records normalized")

with open(PACK + "/pcap_summary.json", encoding="utf-8") as f:
    count = 0
    for line in f:
        if not line.strip():
            continue
        r = json.loads(line)
        ts = datetime.strptime(
            r["start_time"], "%m/%d/%Y %I:%M:%S %p"
        ).replace(tzinfo=timezone.utc)
        events.append({
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "hostname": r.get("hostname"),
            "source_type": "pcap",
            "event_category": "network_flow",
            "severity": None,
            "user": None,
            "process_name": None,
            "process_id": None,
            "src_ip": r.get("src_ip"),
            "src_port": r.get("src_port"),
            "dst_ip": r.get("dst_ip"),
            "dst_port": r.get("dst_port"),
            "protocol": r.get("protocol"),
            "event_id": None,
            "provider": "pcap",
            "raw_message": line.rstrip(),
            "event_data": r,
            "source_origin": "evidence_pack"
        })
        count += 1
print(f"pcap_summary.json   : {count} records normalized")

with open(OUT, "w", encoding="utf-8") as f:
    for r in events:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

with open(ALL, "a", encoding="utf-8") as f:
    for r in events:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

print("appended to normalized_events.json")
print("network_events.json written")
PY
