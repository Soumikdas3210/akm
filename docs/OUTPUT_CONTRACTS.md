# Output Contracts (frozen Week 1) — for Member D

These are the three CSV files the experiment code will produce. Build every plotting script against these exact column names using mock data. If any column needs to change, Member A announces it in the group chat first. The source of truth in code is `akm/schemas.py`.

General rules: one header row, comma-separated, UTF-8. Numbers are plain decimals (no thousands separators, no `%` signs). A column that does not apply to a row holds `-` (text columns) or `0` (numeric columns), as stated per column below.

## scores.csv — one row per (trial × verifier)

| Column | Type | Meaning / allowed values |
|---|---|---|
| run_id | text | e.g. `s17-N10000-b2048-t128` (seed, N, size, tau) |
| seed | int | the run seed |
| N | int | records in the corpus |
| size | int | plaintext payload bytes: 200, 2048, 32768 |
| tau | int | commitment bits: 64, 96, 128, 256 |
| k | int | V1 challenges; `0` for every verifier except V1 |
| fault | text | `F0`, `F1a`, `F1b`, `F2`, `F3`, `F4`, `F5`, `F5b`, `F5c`, `F6`, `F7` |
| eps | float | fraction of records corrupted (0.001, 0.01, 0.05); `0` for single-record faults |
| verifier | text | `V0`, `V1`, `V2minus`, `V2`, `V3` |
| mode | text | `cumulative` for all ladder runs; `sampling` only for V1-S (the RQ4 figure) |
| trial | int | trial number within the cell, starting at 1 |
| verdict | text | `PASS`, `FAIL`, `PARTIAL` (F6 crash runs), `UNRUNNABLE` (F7) |
| tp, fp, fn | int | record-level counts: flagged IDs vs. the fault manifest |
| detected | 0/1 | trial-level outcome under the scoring rules in C's `PREREG.md` |

Example row:
```
s17-N10000-b2048-t128,17,10000,2048,128,0,F5,0,V0,cumulative,1,PASS,0,0,1,0
```
(V0 says PASS on a wrong-DEK rewrap — the predicted miss.)

Detection rate for a cell = mean of `detected` over its trials. Wilson 95 % CIs are computed only for `verifier=V1` cells.

## timings.csv — one row per timed phase × repetition

| Column | Type | Meaning |
|---|---|---|
| run_id, N, size, tau | as above | |
| phase | text | `provision`, `migrate`, `verify` |
| verifier | text | for `verify`: the verifier. For `migrate`: which proof it emitted — `none` (no-proof control), `V0`, `V2minus`, `V2`. For `provision`: `-` |
| fsync_policy | text | `per_record` or `group:<B>` e.g. `group:1000` |
| rep | int | 1–5. The warm-up run is discarded and never written |
| wall_s | float | wall-clock seconds (`time.perf_counter`) |
| cpu_s | float | process CPU seconds (user + system) |
| peak_rss_mb | float | peak resident memory, MB |

Plot the median over `rep` with IQR error bars. Report the P4 ratio (verify ÷ migrate) on **both** `wall_s` and `cpu_s` (Execution Plan issue 8).

## storage.csv — one row per (configuration × verifier)

**Important: the byte columns are the *audit overhead*, not the whole record.**

| Column | Type | Meaning |
|---|---|---|
| run_id, N, size, tau, verifier | as above | |
| tuple_bytes_per_rec | float | extra bytes in the record tuple for auditing: `tau/8` for V2, `0` for V0, V1, V2minus |
| receipt_bytes_per_rec | float | measured receipt-log bytes per record (currently 83 B, fixed format) |
| merkle_bytes_per_rec | float | stored Merkle internal nodes per record (`0` if the tree is not stored) |
| total_bytes_per_rec | float | sum of the three above |
| pct_payload | float | total ÷ `size` × 100 |
| pct_tuple | float | total ÷ base stored tuple × 100 (base tuple = 285 B at 200 B payload) |

Base tuple (no commitment) = `16 + (size + 16) + 12 + 40 + 1` bytes = `size + 85`.

## Receipt format (for reference)

Fixed 83 bytes per record: version (1) · id (16) · epoch (1) · status (1) · H(w_old) (32) · leaf ρ (32). Full rationale in `akm/receipts.py`.


## Changes since the Week-1 freeze (Day 3) — read these, D

1. **timings.csv, `phase = migrate`:** `verifier` is now `none` (no-proof control) or `proof` (receipts + Merkle bundle). The old plan listed `V0`, `V2minus`, `V2` separately, but those rungs audit the *identical* migration (the commitment is installed at provisioning), so three rows would have been one measurement repeated three times.
2. **timings.csv, `phase = verify`:** `fsync_policy` is `-`. Verification is read-only, and the migrated artifact is byte-identical under both policies (tested), so it is measured once. `verifier` values: `V0`, `V1S` (sampling mode, k = 100), `V2minus`, `V2`.
3. **P4 ratio** = median `verify/V2` ÷ median `migrate/proof`, computed separately for `per_record` and `group:1000`, on `wall_s` and on `cpu_s` (4 numbers per configuration).
4. **storage.csv, `merkle_bytes_per_rec`:** non-zero only for `V1`. Only V1's challenge-response needs the *stored* tree; V0, V2⁻ and V2 recompute the root from the receipt log.
5. **RQ4 lives in its own `scores.csv`** (`results/rq4/`), same columns, `mode = sampling`, `verifier = V1`. Plot 95 % Wilson CIs; the pass/fail decision uses the Bonferroni rule (see PREREG addendum). The `fp` and `fn` columns at `k = 500` are the exactness check: `fp` must be 0 everywhere; on F5, `fn` counts damaged records that V1-S challenged and passed.
