#!/bin/bash
set -euo pipefail

OUT="segmentation_rules.json"

jq -n '
{
  zones: [
    {name: "DMZ", cidr: "10.10.10.0/24", purpose: "public-facing services", default_inbound: "drop", default_outbound: "accept with restrictions"},
    {name: "INTERNAL", cidr: "10.20.20.0/24", purpose: "clinical applications and databases", default_inbound: "drop", default_outbound: "accept with restrictions"},
    {name: "MGMT", cidr: "10.30.30.0/24", purpose: "administration", default_inbound: "drop", default_outbound: "accept with restrictions"},
    {name: "MEDDEV", cidr: "10.40.40.0/24", purpose: "medical device VLAN", default_inbound: "drop", default_outbound: "accept with restrictions"}
  ],
  flows: [
    {src_zone: "MGMT", dst_zone: "INTERNAL", proto: "tcp", dport: 22, justification: "administration", exception_for: null},
    {src_zone: "MGMT", dst_zone: "DMZ", proto: "tcp", dport: 22, justification: "administration", exception_for: null},
    {src_zone: "INTERNAL", dst_zone: "INTERNAL", proto: "tcp", dport: 443, justification: "clinical workstations to server hosts", exception_for: null},
    {src_zone: "INTERNAL", dst_zone: "INTERNAL", proto: "tcp", dport: 3306, justification: "clinical workstations to server hosts", exception_for: null},
    {src_zone: "DMZ", dst_zone: "INTERNAL", proto: "tcp", dport: 3306, justification: "named DMZ application hosts to INTERNAL databases", exception_for: null},
    {src_zone: "MEDDEV", dst_zone: "INTERNAL", proto: "tcp", dport: 4242, justification: "DICOM imaging to PACS", exception_for: null},
    {src_zone: "MEDDEV", dst_zone: "INTERNAL", proto: "tcp", dport: 443, justification: "EHR web integration for device display", exception_for: null},
    {src_zone: "ALL", dst_zone: "MGMT", proto: "udp", dport: 53, justification: "DNS resolution", exception_for: null},
    {src_zone: "ALL", dst_zone: "MGMT", proto: "tcp", dport: 53, justification: "DNS resolution", exception_for: null},
    {src_zone: "MGMT", dst_zone: "MEDDEV", proto: "tcp", dport: 22, justification: "administration of medical devices", exception_for: null},
    {src_zone: "MGMT", dst_zone: "MEDDEV", proto: "tcp", dport: 4242, justification: "DICOM administration", exception_for: null},
    {src_zone: "DMZ", dst_zone: "MEDDEV", proto: "any", dport: 0, justification: "deny_all", exception_for: null},
    {src_zone: "INTERNAL", dst_zone: "MEDDEV", proto: "any", dport: 0, justification: "deny_all", exception_for: null},
    {src_zone: "MEDDEV", dst_zone: "DMZ", proto: "any", dport: 0, justification: "deny_all", exception_for: null},
    {src_zone: "MEDDEV", dst_zone: "INTERNET", proto: "any", dport: 0, justification: "deny_all", exception_for: null},
    {src_zone: "DMZ", dst_zone: "MGMT", proto: "any", dport: 0, justification: "deny_all", exception_for: null},
    {src_zone: "INTERNAL", dst_zone: "MGMT", proto: "any", dport: 0, justification: "deny_all", exception_for: null}
  ]
} as $base
| $base
| .summary = {
    flow_count: ($base.flows | length),
    allow_count: ($base.flows | map(select(.justification != "deny_all")) | length),
    deny_count: ($base.flows | map(select(.justification == "deny_all")) | length),
    cross_zone_pairs: ($base.flows | map({src: .src_zone, dst: .dst_zone}) | unique | length)
  }
' > "$OUT"

echo "Segmentation rules written to $OUT"
