# Results report (generated — do not edit by hand)

Regenerate with `python -m akm.run report`. Every number below comes from the CSVs.

## T1 — Experiment 1: detection matrix

| Fault | V0 | V1 | V2⁻ | V2 | V3 |
|---|---|---|---|---|---|
| F0 | FP 0/100 | FP 0/100 | FP 0/100 | FP 0/100 | FP 0/100 |
| F1a | 100% | 100% | 100% | 100% | 100% |
| F1b | 100% | 100% | 100% | 100% | 100% |
| F2 | 100% | 100% | 100% | 100% | 100% |
| F3 | 100% | 100% | 100% | 100% | 100% |
| F4r | 100% | 100% | 100% | 100% | 100% |
| F4m | 100% | 100% | 100% | 100% | 100% |
| F5 | 0% | 0% | 100% | 100% | 100% |
| F5 @ ε=0.05 | 0% | 0% | 100% | 100% | 100% |
| F5b | 0% | 0% | 100% | 100% | 100% |
| F5c | 0% | 0% | 100% | 100% | 100% |
| F6 | 100% | 100% | 100% | 100% | 100% |
| F7 | n/a | n/a | 0% | 100% | n/a |

Quality gate 2:
- [PASS] F0: zero false positives everywhere
- [PASS] V0 and V1 read 0% on F5, F5b, F5c
- [PASS] V2 and V2minus read 100% on F5, F5b, F5c
- [PASS] F7: V2minus 0%, V2 100%
- [PASS] No row other than F7 separates V2minus from V2 (P6)

## T2 — RQ4: V1-S at k = 100

| Fault | ε | damaged m | detected | 95% CI | theory | trials |
|---|---|---|---|---|---|---|
| F1b | 0.1% | 10 | 0.091 | [0.075, 0.110] | 0.095 | 1000 |
| F1b | 1% | 100 | 0.634 | [0.604, 0.663] | 0.634 | 1000 |
| F1b | 5% | 500 | 0.995 | [0.988, 0.998] | 0.994 | 1000 |
| F3 | 0.1% | 10 | 0.103 | [0.086, 0.123] | 0.095 | 1000 |
| F3 | 1% | 100 | 0.616 | [0.585, 0.646] | 0.634 | 1000 |
| F3 | 5% | 500 | 0.994 | [0.987, 0.997] | 0.994 | 1000 |
| F5 | 0.1% | 10 | 0.000 | [0.000, 0.004] | 0 (Cor. 1.1) | 1000 |
| F5 | 1% | 100 | 0.000 | [0.000, 0.004] | 0 (Cor. 1.1) | 1000 |
| F5 | 5% | 500 | 0.000 | [0.000, 0.004] | 0 (Cor. 1.1) | 1000 |

- 95% CI misses among F1b/F3 cells (all k): 3 of 48 (~2.4 expected by chance)
- Bonferroni-adjusted misses: 1
- F5 cells with any detection: 0
- **P2 (Addendum A1 rule): FAIL**

## T3 — Experiment 2: wall-clock seconds, median (IQR)

| N | size B | mig none (fsync/rec) | mig proof (fsync/rec) | mig none (group) | mig proof (group) | V0 | V1-S | V2⁻ | V2 |
|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 200 | 20.176 (0.249) | 25.245 (2.082) | 0.264 (0.007) | 0.296 (0.005) | 0.058 (0.002) | 0.020 (0.001) | 0.150 (0.003) | 0.106 (0.001) |
| 1,000 | 2048 | 22.916 (2.605) | 34.218 (1.243) | 0.277 (0.007) | 0.319 (0.008) | 0.067 (0.001) | 0.021 (0.003) | 0.151 (0.003) | 0.113 (0.001) |
| 10,000 | 200 | 266.141 (5.571) | 345.348 (3.224) | 2.969 (0.030) | 3.106 (0.039) | 0.544 (0.004) | 0.062 (0.001) | 1.367 (0.011) | 0.967 (0.004) |
| 10,000 | 2048 | 287.831 (0.271) | 355.838 (3.652) | 3.029 (0.068) | 3.135 (0.064) | 0.587 (0.019) | 0.058 (0.002) | 1.390 (0.017) | 1.019 (0.016) |

## T4 — P4 ratios (V2 verify ÷ proof migration; ✓ = below 0.10)

| N | size B | fsync/rec wall | fsync/rec CPU | group wall | group CPU |
|---|---|---|---|---|---|
| 1,000 | 200 | 0.004 ✓ | 0.067 ✓ | 0.357 ✗ | 0.434 ✗ |
| 1,000 | 2048 | 0.003 ✓ | 0.070 ✓ | 0.354 ✗ | 0.431 ✗ |
| 10,000 | 200 | 0.003 ✓ | 0.061 ✓ | 0.311 ✗ | 0.389 ✗ |
| 10,000 | 2048 | 0.003 ✓ | 0.063 ✓ | 0.325 ✗ | 0.404 ✗ |

## T5 — Storage per record (bytes)

| size B | τ | verifier | commitment | receipt log | stored tree | total | % payload |
|---|---|---|---|---|---|---|---|
| 200 | 64 | V2 | 8.0 | 83.0 | 0.0 | 91.0 | 45.50% |
| 200 | 96 | V2 | 12.0 | 83.0 | 0.0 | 95.0 | 47.50% |
| 200 | 128 | V0 | 0.0 | 83.0 | 0.0 | 83.0 | 41.50% |
| 200 | 128 | V1 | 0.0 | 83.0 | 32.0 | 115.0 | 57.51% |
| 200 | 128 | V2⁻ | 0.0 | 83.0 | 0.0 | 83.0 | 41.50% |
| 200 | 128 | V2 | 16.0 | 83.0 | 0.0 | 99.0 | 49.50% |
| 200 | 256 | V2 | 32.0 | 83.0 | 0.0 | 115.0 | 57.50% |
| 2048 | 64 | V2 | 8.0 | 83.0 | 0.0 | 91.0 | 4.44% |
| 2048 | 96 | V2 | 12.0 | 83.0 | 0.0 | 95.0 | 4.64% |
| 2048 | 128 | V0 | 0.0 | 83.0 | 0.0 | 83.0 | 4.05% |
| 2048 | 128 | V1 | 0.0 | 83.0 | 32.0 | 115.0 | 5.62% |
| 2048 | 128 | V2⁻ | 0.0 | 83.0 | 0.0 | 83.0 | 4.05% |
| 2048 | 128 | V2 | 16.0 | 83.0 | 0.0 | 99.0 | 4.83% |
| 2048 | 256 | V2 | 32.0 | 83.0 | 0.0 | 115.0 | 5.62% |

P7: PASS (receipt log larger than the commitment field at every τ ≤ 128)

## T6 — Setup

| Item | e1 | rq4 | e2 |
|---|---|---|---|
| CPU | AMD Ryzen 7 7435HS | AMD Ryzen 7 7435HS | AMD Ryzen 7 7435HS |
| OS | Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.3 | Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.3 | Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.3 |
| Python | 3.12.3 | 3.12.3 | 3.12.3 |
| cryptography | 46.0.6 | 46.0.6 | 46.0.6 |
| PREREG commit | 2adc7f5ff0d719628ead25963d18e2f8da8eb1b2 | 2adc7f5ff0d719628ead25963d18e2f8da8eb1b2 | 2adc7f5ff0d719628ead25963d18e2f8da8eb1b2 |
| code commit | 2adc7f5ff0d719628ead25963d18e2f8da8eb1b2 | da85c397c23061915f050f386d52a07a5edbfa35 | 263f61b85897c1ef4f1a89d1d829cd7db074021b |
| smoke run? | False | False | False |
| disk (E2) | {"mount": "/dev/sdd ext4", "rotational": true} |  |  |

## Key numbers for the text

- E1: 100 seeds per cell.
- E1: V0 detected 0 of 400 wrong-key trials (F5, F5b, F5c combined); V2 detected 400 of 400.
- E1: 0 false positives in 500 honest (F0) verifier-trials.
- RQ4: V1-S directly challenged 29928 wrong-key records (F5) and passed every one.
- RQ4: innocent records flagged across all trials: 0.
- RQ4: P2 under the pre-registered Bonferroni rule: FAIL.
- E2: P4 ratio [per_record, wall] ranges 0.003–0.004 across 4 configurations (4 below 0.10).
- E2: P4 ratio [per_record, cpu] ranges 0.061–0.070 across 4 configurations (4 below 0.10).
- E2: P4 ratio [group:1000, wall] ranges 0.311–0.357 across 4 configurations (0 below 0.10).
- E2: P4 ratio [group:1000, cpu] ranges 0.389–0.434 across 4 configurations (0 below 0.10).
- E2: receipt log = 83 B/record; commitment = τ/8 = 8–32 B/record.
