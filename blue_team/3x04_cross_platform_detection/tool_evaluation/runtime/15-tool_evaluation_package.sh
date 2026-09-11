#!/bin/bash

PACKAGE="tool_evaluation"

required=(
    "findings/anchor_cli.json"
    "findings/anchor_export.json"
    "findings/scenario_a_cli.json"
    "findings/scenario_a_export.json"
    "findings/scenario_b_cli.json"
    "findings/scenario_b_export.json"
    "findings/scenario_c_cli.json"
    "findings/scenario_c_export.json"
    "comparison/tradeoff_table.json"
    "comparison/tradeoff_table.md"
    "comparison/workflow_comparison.json"
    "playbook/tool_agnostic_playbook.md"
    "brief/vendor_brief.md"
    "workspace/workspace_init.json"
)

for file in "${required[@]}"; do
    if [ ! -s "$file" ]; then
        echo "ERROR: required file missing or empty: $file" >&2
        exit 1
    fi
done

rm -rf "$PACKAGE"

mkdir -p \
    "$PACKAGE/findings" \
    "$PACKAGE/comparison" \
    "$PACKAGE/playbook" \
    "$PACKAGE/brief" \
    "$PACKAGE/workspace" \
    "$PACKAGE/runtime"

cp findings/*.json "$PACKAGE/findings/"
echo "copying findings   ... 8 files"

cp comparison/tradeoff_table.json \
   comparison/tradeoff_table.md \
   comparison/workflow_comparison.json \
   "$PACKAGE/comparison/"
echo "copying comparison ... 3 files"

cp playbook/tool_agnostic_playbook.md "$PACKAGE/playbook/"
echo "copying playbook   ... 1 file"

cp brief/vendor_brief.md "$PACKAGE/brief/"
echo "copying brief      ... 1 file"

cp workspace/workspace_init.json "$PACKAGE/workspace/"
echo "copying workspace  ... 1 file"

runtime_count=0
for script in ./*.sh; do
    name=$(basename "$script")

    if [ "$name" != "15-tool_evaluation_package.sh" ]; then
        cp "$script" "$PACKAGE/runtime/"
        runtime_count=$((runtime_count + 1))
    fi
done

cp 15-tool_evaluation_package.sh "$PACKAGE/runtime/"
runtime_count=$((runtime_count + 1))

echo "copying runtime    ... $runtime_count files"

manifest_tmp=$(mktemp)
trap 'rm -f "$manifest_tmp"' EXIT

find "$PACKAGE" -type f ! -name 'MANIFEST.json' -print0 |
    sort -z |
    while IFS= read -r -d '' file; do
        relative=${file#"$PACKAGE/"}
        size=$(stat -c '%s' "$file")
        hash=$(sha256sum "$file" | awk '{print $1}')

        jq -n \
            --arg path "$relative" \
            --argjson size "$size" \
            --arg sha256 "$hash" \
            '{path:$path,size:$size,sha256:$sha256}'
    done | jq -s '.' > "$manifest_tmp"

mv "$manifest_tmp" "$PACKAGE/MANIFEST.json"
trap - EXIT

entries=$(jq 'length' "$PACKAGE/MANIFEST.json")

while IFS= read -r file; do
    if [ ! -s "$file" ]; then
        echo "ERROR: package file missing or empty: $file" >&2
        exit 1
    fi
done < <(find "$PACKAGE" -type f)

echo "MANIFEST.json      : $entries entries"
echo "sanity check       : ok"
echo "tool_evaluation/ ready"
