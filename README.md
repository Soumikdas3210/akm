# AKM — Auditable Key Migration (Group 01, COE4232)

Experiment code for *Auditable Key Migration: External Verification of Cryptographic Key Rotation and Its Cost*.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -v                       # all tests should pass
python -m akm.pipeline --seed 1 --seeds 10 --N 1000   # honest runs, all verifiers
```

## Layout

| File | Stage | Status |
|---|---|---|
| `akm/config.py` | P0 run config + seeded DRBG | ✅ |
| `akm/corpus.py` | P1 synthetic records | ✅ |
| `akm/store.py` | storage (payload.db + wraps.db) | ✅ |
| `akm/provision.py` | P2 DEK, AES-GCM, AES-KW, commitment | ✅ |
| `akm/inventory.py` | P3 anchor-signed inventory | ✅ |
| `akm/migrate.py` | P4 Algorithm 1 + fault hooks + crash/resume | ✅ |
| `akm/receipts.py` | 83-B receipt format + durable log | ✅ |
| `akm/merkle.py` | P6 Merkle root + signed bundle | ✅ |
| `akm/verifiers/common.py` | shared structural (V0) layer, verdicts | ✅ |
| `akm/verifiers/v0.py, v2minus.py, v2.py, v3.py` | P7 verifiers | ✅ |
| `akm/pipeline.py` | end-to-end honest run | ✅ |
| `akm/verifiers/v1.py`, `akm/prover.py` | V1 cumulative + V1-S, challenge-response | ✅ |
| `akm/faults.py` | P5 fault harness + manifest | ✅ |
| `akm/score.py` | P8 scoring, V3 cross-check, Wilson CI | ✅ |
| `akm/guard.py`, `akm/isolated.py`, `akm/keys_stage.py`, `akm/isolation_probe.py` | key isolation | ✅ |
| `Dockerfile`, `docker-compose.yml` | formal isolation (untested in authoring sandbox) | ⚠️ test locally |
| `akm/run.py` | CLI: e1, summarize, rq4, rq4-summary, e2, e2-summary | ✅ |
| `akm/exp_rq4.py` | RQ4 sampling sweep + Bonferroni summary | ✅ |
| `akm/exp_e2.py`, `akm/bench.py` | Experiment 2 cost: timings.csv, storage.csv | ✅ |
| `akm/analysis.py`, `akm/report.py` | shared aggregation; REPORT.md + LaTeX tables T1–T6 | ✅ |
| `akm/repro.py` | repro-check: re-run rows must match originals exactly | ✅ |
| `akm/freeze.py` | MANIFEST.json checksums, code + PREREG commits, verify | ✅ |
| `akm/draft.py` | outcome-driven LaTeX drafts (Setup, Results, Threats) with numbers as macros | ✅ |
| `akm/demo.py` | 15-second narrated live demonstration for the defense | ✅ |
| `docs/DEFENSE.md` | likely defense questions, answers, and proof commands | ✅ |

## Rules
Experiment-only DRBG: all "random" bytes derive from the run seed. Never use this code for real keys. No verifier may read `fault_manifest.json`. `runs/` is never committed.
