#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
import os
import ipaddress

INPUT = "cleaned_events.json"
ASSET_FILE = os.path.expanduser(
    "~/evidence_pack_primary/context/asset_inventory.json"
)
ZONE_FILE = os.path.expanduser(
    "~/evidence_pack_primary/context/network_zones.json"
)
OUTPUT = "enriched_events.json"


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_assets(data):
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("assets", [])
    else:
        items = []

    assets = {}

    for item in items:
        if not isinstance(item, dict):
            continue

        hostname = item.get("hostname") or item.get("host")
        if hostname:
            assets[str(hostname).lower()] = {
                "role": item.get("role"),
                "criticality": item.get("criticality"),
                "os": item.get("os"),
                "owner": item.get("owner"),
                "zone": item.get("zone")
            }

    return assets


def load_zones(data):
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("zones", [])
    else:
        items = []

    networks = []

    for zone in items:
        if not isinstance(zone, dict):
            continue

        zone_name = zone.get("zone") or zone.get("name")
        cidrs = zone.get("cidrs") or zone.get("networks") or []

        if isinstance(cidrs, str):
            cidrs = [cidrs]

        for cidr in cidrs:
            try:
                networks.append(
                    (ipaddress.ip_network(cidr, strict=False), zone_name)
                )
            except ValueError:
                continue

    networks.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return networks


def resolve_zone(value, networks):
    if not value:
        return "unknown"

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"

    for network, zone in networks:
        if ip in network:
            return zone

    return "unknown"


assets = load_assets(load_json(ASSET_FILE))
networks = load_zones(load_json(ZONE_FILE))

total = 0
asset_count = 0
src_count = 0
dst_count = 0
unknown_hosts = 0

with open(INPUT, encoding="utf-8", errors="replace") as src, \
     open(OUTPUT, "w", encoding="utf-8") as out:

    for line in src:
        if not line.strip():
            continue

        event = json.loads(line)
        total += 1

        hostname = event.get("hostname")
        asset = assets.get(str(hostname).lower()) if hostname else None

        if asset:
            event["asset"] = asset
            asset_count += 1
        else:
            event["asset"] = {
                "role": None,
                "criticality": None,
                "os": None,
                "owner": None,
                "zone": None
            }
            unknown_hosts += 1

        if event.get("src_ip"):
            event["src_zone"] = resolve_zone(
                event["src_ip"], networks
            )
            if event["src_zone"] != "unknown":
                src_count += 1
        else:
            event["src_zone"] = "unknown"

        if event.get("dst_ip"):
            event["dst_zone"] = resolve_zone(
                event["dst_ip"], networks
            )
            if event["dst_zone"] != "unknown":
                dst_count += 1
        else:
            event["dst_zone"] = "unknown"

        out.write(
            json.dumps(
                event,
                separators=(",", ":"),
                ensure_ascii=False
            ) + "\n"
        )

def pct(n, total):
    return (n / total * 100) if total else 0.0

print(f"events processed    : {total}")
print(
    f"asset context added : {asset_count} "
    f"({pct(asset_count, total):.2f}%)"
)
print(
    f"src_zone resolved   : {src_count} "
    f"({pct(src_count, total):.2f}%)"
)
print(
    f"dst_zone resolved   : {dst_count} "
    f"({pct(dst_count, total):.2f}%)"
)
print(f"unknown hosts       : {unknown_hosts}")
print("enriched_events.json written")
PY
