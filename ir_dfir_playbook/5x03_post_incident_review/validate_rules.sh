
#!/bin/bash
set -euo pipefail

DATA="$HOME/Downloads/lessons_learned/5x03"

for rule in process network; do
    echo "Rule: $rule"

    for sample in incident clean; do
        file="$DATA/${sample}_sysmon.jsonl"
        total=$(wc -l < "$file")

        if [[ "$rule" == "process" ]]; then
            filter='select(.event_id == 1 and
              ((.parent_image // "" | ascii_downcase) |
                test("\\\\(powershell|pwsh|wscript|cscript)\\.exe$")) and
              ((.image // "" | ascii_downcase) |
                test("\\\\(msbuild|csc|vbc|jsc)\\.exe$")))'
        else
            filter='select(.event_id == 3 and
              .initiated == true and
              ((.image // "" | ascii_downcase) |
                test("\\\\(msbuild|csc|vbc|jsc)\\.exe$")) and
              ((.dst_hostname // "" | ascii_downcase) |
                endswith(".nuget.org") | not))'
        fi

        matches=$(jq -c "$filter" "$file")
        count=$(printf '%s\n' "$matches" |
            grep -c '^{' || true)

        rate=$(awk -v n="$count" -v t="$total" \
            'BEGIN {printf "%.3f", t ? 100*n/t : 0}')

        echo "  [$sample]"
        echo "  Total events: $total"
        echo "  Matches: $count"
        echo "  Match rate: $rate%"

        if [[ "$sample" == "clean" && "$count" -gt 0 ]]; then
            echo "  Matched baseline events:"
            printf '%s\n' "$matches" |
                jq -r '[.ts, .host, .image,
                  (.dst_hostname // "no destination")] | @tsv'
        fi
    done
done
