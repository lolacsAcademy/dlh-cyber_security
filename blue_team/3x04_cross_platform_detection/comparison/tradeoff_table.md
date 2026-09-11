# Interface Trade-off Analysis

| Scenario | CLI Time | Export Time | Time Delta | CLI Actions | Export Actions | Action Delta | Faster | Cause |
|---|---:|---:|---:|---:|---:|---:|---|---|
| anchor | 21s | 1s | -20s | 5 | 7 | 2 | wazuh_export | native_field_surface |
| scenario_a | 21s | 0s | -21s | 4 | 7 | 3 | wazuh_export | timeline_visualization |
| scenario_b | 21s | 1s | -20s | 5 | 8 | 3 | wazuh_export | filter_bar_efficiency |
| scenario_c | 0s | 1s | 1s | 5 | 7 | 2 | cli | pipeline_expressiveness |

Export advantages: 3

CLI advantages: 1
