# Evaluation Report

Cases: 1200
Successfully evaluated: 1196
Failed: 4
Unparseable: 0
Coverage: 99.67%

## Binary vulnerability detection
Accuracy: 0.4574
Precision: 0.9307
Recall: 0.3771
F1: 0.5368

## Per-CWE binary metrics
| CWE | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 | 99 | 60 | 101 | 936 | 0.6226 | 0.4950 | 0.5515 |
| CWE-78 | 58 | 4 | 140 | 994 | 0.9355 | 0.2929 | 0.4462 |
| CWE-79 | 39 | 14 | 160 | 983 | 0.7358 | 0.1960 | 0.3095 |
| CWE-89 | 61 | 7 | 139 | 989 | 0.8971 | 0.3050 | 0.4552 |
| CWE-798 | 74 | 13 | 126 | 983 | 0.8506 | 0.3700 | 0.5157 |

## Safe-code metrics
Correctly identified safe: 171/199
False positive rate: 0.1407

## Metric definitions
Failed API calls and invalid responses are excluded from all prediction metrics. Vulnerability-level metrics treat any CWE finding as vulnerable. Per-CWE metrics are one-vs-rest. Multiclass metrics use exact CWE for a single finding, SAFE-PYTHON for no findings, and MULTIPLE for multiple distinct CWEs. Macro averages weight observed classes equally; weighted averages weight by support; micro averages aggregate binary decisions.
