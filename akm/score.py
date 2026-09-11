"""
P8 — Scoring ("the grader").

Compares each verifier's verdict with the fault manifest (the answer key)
and appends rows to scores.csv (columns frozen in schemas.py).

Scoring rules — IDENTICAL to PREREG.md:
  F0                  never "detected"; any FAIL is a FALSE POSITIVE
  F1a F1b F2 F3 F5 F5b F5c
                      detected = verdict FAIL and >= 1 true target flagged
                      (a FAIL that flags only innocent records does NOT count)
  F4r F4m             detected = verdict FAIL (global evidence faults)
  F6                  detected = verdict INCOMPLETE and reported flipped set
                      == true flipped set exactly; PASS scores 0
  F7                  detected = verifier ran (not UNRUNNABLE) and flagged the
                      F5 target; rows only for V2minus and V2 (others n/a)
  V1-S (sampling)     detected = verdict FAIL

Ground-truth cross-check (Methodology §3.12): V3 shares our codebase, so it
is not trusted alone. For F0/F3/F5/F5b/F5c, V3's flagged set must EQUAL the
manifest's targets. If not -> GroundTruthConflict, and the driver stops.
"""
from __future__ import annotations

import math
from pathlib import Path

from .schemas import SCORES_COLUMNS, append_row

RECORD_FAULTS = {"F1a", "F1b", "F2", "F3", "F5", "F5b", "F5c"}
GLOBAL_FAULTS = {"F4r", "F4m"}
TRUTH_CHECKED = {"F0", "F3", "F5", "F5b", "F5c"}


class GroundTruthConflict(RuntimeError):
    pass


def cross_check(manifest: dict, v3: dict) -> None:
    f = manifest["fault"]
    if f not in TRUTH_CHECKED:
        return
    truth = set(v3["flagged"])
    if truth != set(manifest["targets"]):
        raise GroundTruthConflict(
            f"{f} seed {manifest['seed']}: V3 flagged {sorted(truth)[:5]}... "
            f"but manifest says {manifest['targets'][:5]}...")


def detected(fault: str, verdict: dict, manifest: dict, mode: str = "cumulative") -> tuple[int, int, int, int]:
    """Return (detected, tp, fp, fn) for one verifier on one trial."""
    flagged = set(verdict["flagged"])
    targets = set(manifest["targets"])
    tp, fp, fn = len(flagged & targets), len(flagged - targets), len(targets - flagged)
    v = verdict["verdict"]
    if mode == "sampling":
        return int(v == "FAIL"), tp, fp, fn
    if fault == "F0":
        return 0, tp, fp, fn
    if fault in RECORD_FAULTS or fault == "F7":
        return int(v == "FAIL" and tp > 0), tp, fp, fn
    if fault in GLOBAL_FAULTS:
        return int(v == "FAIL"), tp, fp, fn
    if fault == "F6":
        ok = v == "INCOMPLETE" and set(verdict.get("flipped") or []) == set(manifest["expected_flipped"])
        return int(ok), tp, fp, fn
    raise ValueError(f"unknown fault {fault}")


def score_trial(csv_path: str | Path, meta: dict, manifest: dict, verdicts: dict[str, dict],
                v3: dict | None = None) -> list[dict]:
    """meta: run_id, seed, N, size, tau, k, trial. verdicts: name -> verdict dict.
    Appends one row per verifier; returns the rows."""
    if v3 is not None:
        cross_check(manifest, v3)
    fault = manifest["fault"]
    rows = []
    for name, vd in verdicts.items():
        mode = vd.get("mode", "cumulative")
        d, tp, fp, fn = detected(fault, vd, manifest, mode)
        row = {
            "run_id": meta["run_id"], "seed": meta["seed"], "N": meta["N"], "size": meta["size"],
            "tau": meta["tau"], "k": meta["k"] if name == "V1" else 0, "fault": fault,
            "eps": manifest["eps"], "verifier": name, "mode": mode, "trial": meta["trial"],
            "verdict": vd["verdict"], "tp": tp, "fp": fp, "fn": fn, "detected": d,
        }
        append_row(csv_path, SCORES_COLUMNS, row)
        rows.append(row)
    return rows


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score 95 % interval — reliable near 0 and 1 (Methodology §3.12)."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = 0.0 if successes == 0 else max(0.0, centre - half)   # exact at the boundaries,
    hi = 1.0 if successes == n else min(1.0, centre + half)   # no floating-point dust
    return (lo, hi)
