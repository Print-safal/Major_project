# Illustrative Evaluation Report

This small example shows report formatting only; these are controlled mock values, not benchmark results.

Cases: 4  
Successfully evaluated: 3  
Failed: 1  
Unparseable: 0  
Coverage: 75.00%

## Binary vulnerability detection

Accuracy: 0.6667  
Precision: 0.5000  
Recall: 1.0000  
F1: 0.6667

## Per-CWE binary metrics

| CWE | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-78 | 1 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| CWE-89 | 0 | 1 | 0 | 2 | 0.0000 | 0.0000 | 0.0000 |

## Safe-code metrics

Correctly identified safe: 1/2  
False positive rate: 0.5000

Failed or invalid cases are visible in outputs and excluded from predictive metrics.
