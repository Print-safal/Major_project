# Evaluation Report

Cases: 1200
Successfully evaluated: 1198
Failed: 2
Unparseable: 0
Coverage: 99.83%

## Binary vulnerability detection
Accuracy: 0.4708
Precision: 0.9354
Recall: 0.3918
F1: 0.5523

## Per-CWE binary metrics
| CWE | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 | 102 | 57 | 98 | 941 | 0.6415 | 0.5100 | 0.5682 |
| CWE-78 | 65 | 4 | 134 | 995 | 0.9420 | 0.3266 | 0.4851 |
| CWE-79 | 43 | 16 | 156 | 983 | 0.7288 | 0.2161 | 0.3333 |
| CWE-89 | 60 | 7 | 140 | 991 | 0.8955 | 0.3000 | 0.4494 |
| CWE-798 | 73 | 12 | 127 | 986 | 0.8588 | 0.3650 | 0.5123 |

## Safe-code metrics
Correctly identified safe: 173/200
False positive rate: 0.1350

## Metric definitions
Failed API calls and invalid responses are excluded from all prediction metrics. Vulnerability-level metrics treat any CWE finding as vulnerable. Per-CWE metrics are one-vs-rest. Multiclass metrics use exact CWE for a single finding, SAFE-PYTHON for no findings, and MULTIPLE for multiple distinct CWEs. Macro averages weight observed classes equally; weighted averages weight by support; micro averages aggregate binary decisions.
