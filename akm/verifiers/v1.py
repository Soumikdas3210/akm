"""
V1 — the spot-checker. Holds NO keys; challenges the migrator on k records.

Two modes (Execution Plan issue 1):

  cumulative  (fault matrix)  = V0's full structural scan + k challenges.
              Since V0 already reads every record, challenges add nothing:
              predicted identical to V0 — 100 % on F0-F4, 0 % on F5.

  sampling    (RQ4, "V1-S")   = O(1) global checks + k challenges ONLY.
              A cheaper ALTERNATIVE to V0's full scan, not a rung above it.
              Global checks: inventory signature, bundle signature, and
              n_receipts == N (this is why F1a is caught deterministically).
              Detection on F1b/F3 should follow 1-(1-eps)^k; on F5 it is 0,
              because a keyless verifier has no check to run on a wrap.

Challenge indices (Decision 3, PREREG):
    idx_j = SHA-256("AKM-chal-v1" || MR || beacon || j) mod N,  j = 1..k,
    sampled WITH replacement so the textbook formula is exact (issue 12).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path

from ..inventory import load_verified_inventory
from ..merkle import verify_bundle_signature, verify_inclusion
from ..prover import Prover
from ..receipts import STATUS_OK, Receipt
from ..store import EPOCH_NEW
from .common import FAIL, PASS, Structural, Verdict, combine, structural_checks

NAME = "V1"
CHAL_TAG = b"AKM-chal-v1"


def challenge_indices(MR: bytes, beacon: int, k: int, N: int) -> list[int]:
    return [int.from_bytes(hashlib.sha256(
                CHAL_TAG + MR + beacon.to_bytes(8, "big") + j.to_bytes(8, "big")).digest(), "big") % N
            for j in range(1, k + 1)]


def check_answer(rid: bytes, ans: dict, MR: bytes) -> list[str]:
    """Everything a keyless verifier can check about one challenged record."""
    if ans["receipt"] is None:
        return ["challenge: no receipt for this record"]
    if not verify_inclusion(ans["receipt"], ans["proof"], MR):
        return ["challenge: receipt not in the signed Merkle tree"]
    r = Receipt.decode(ans["receipt"])
    if r.rid != rid:
        return ["challenge: receipt belongs to another record"]
    if ans["w_new"] is None:
        return ["challenge: receipt claims migration but no new wrap is stored"]
    if not r.matches(ans["w_new"], ans["ct"]):
        return ["challenge: receipt does not match stored wrap/ciphertext"]
    if r.status != STATUS_OK or r.epoch != EPOCH_NEW:
        return ["challenge: receipt status/epoch invalid"]
    return []            # <- a wrong-DEK wrap always reaches here: nothing left to check


def _global_checks(run_dir: Path):
    """O(1) checks for V1-S. Returns (ids, MR, notes, fatal)."""
    ids, why = load_verified_inventory(run_dir)
    if ids is None:
        return None, None, [why], True
    try:
        bundle = json.loads((run_dir / "bundle.json").read_text())
    except FileNotFoundError:
        return ids, None, ["bundle.json missing"], True
    if not verify_bundle_signature(bundle, run_dir / "pub" / "migrator.pub"):
        return ids, None, ["bundle signature invalid"], True
    notes = []
    if bundle["n_receipts"] != len(ids):
        notes.append(f"receipt count {bundle['n_receipts']} != inventory N {len(ids)}")
    if bundle["N"] != len(ids):
        notes.append("bundle N differs from the anchored inventory")
    if bundle["claimed"] != "COMPLETE":
        notes.append("bundle does not claim a complete migration")
    return ids, bytes.fromhex(bundle["MR"]), notes, False


def verify_sampling(run_dir: str | Path, k: int, beacon: int, prover: Prover | None = None) -> Verdict:
    """V1-S: never calls structural_checks(); touches only k records."""
    run_dir = Path(run_dir)
    t0 = time.perf_counter()
    ids, MR, notes, fatal = _global_checks(run_dir)
    if fatal:
        return Verdict(NAME, FAIL, {}, None, notes, time.perf_counter() - t0)
    own = prover is None
    prover = prover or Prover(run_dir)
    flags = defaultdict(list)
    try:
        for idx in challenge_indices(MR, beacon, k, len(ids)):
            reasons = check_answer(ids[idx], prover.answer(ids[idx]), MR)
            if reasons:
                flags[ids[idx].hex()].extend(reasons)
    finally:
        if own:
            prover.close()
    verdict = FAIL if (flags or notes) else PASS
    return Verdict(NAME, verdict, dict(flags), None, notes, time.perf_counter() - t0)


def first_failures(run_dir: str | Path, beacons: list[int], k_max: int) -> list[int | None]:
    """RQ4 helper: for each beacon, the 1-based position of the first failing
    challenge in its sequence (None if all k_max pass). Then 'detected at k'
    is simply first_failure <= k — one pass gives every k in the sweep.
    A global-check failure is reported as position 0 (detected at every k)."""
    run_dir = Path(run_dir)
    ids, MR, notes, fatal = _global_checks(run_dir)
    if fatal or notes:
        return [0] * len(beacons)
    prover = Prover(run_dir)
    out = []
    try:
        for b in beacons:
            pos = None
            for j, idx in enumerate(challenge_indices(MR, b, k_max, len(ids)), start=1):
                if check_answer(ids[idx], prover.answer(ids[idx]), MR):
                    pos = j
                    break
            out.append(pos)
    finally:
        prover.close()
    return out


def challenge_traces(run_dir: str | Path, beacons: list[int], k_max: int):
    """RQ4 helper with full detail. For each beacon: the list of k_max
    (record_hex, failed) pairs in challenge order. Returns (global_fail, traces).
    Detection at k = any failure in the first k; tp/fp/fn come from comparing
    the failed records in that prefix with the manifest."""
    run_dir = Path(run_dir)
    ids, MR, notes, fatal = _global_checks(run_dir)
    if fatal or notes:
        return True, []
    prover = Prover(run_dir)
    cache: dict[int, bool] = {}
    traces = []
    try:
        for b in beacons:
            tr = []
            for idx in challenge_indices(MR, b, k_max, len(ids)):
                if idx not in cache:        # same record, same answer: check once
                    cache[idx] = bool(check_answer(ids[idx], prover.answer(ids[idx]), MR))
                tr.append((ids[idx].hex(), cache[idx]))
            traces.append(tr)
    finally:
        prover.close()
    return False, traces


def challenge_flags(run_dir: Path, k: int, beacon: int) -> tuple[dict, list]:
    """The challenge part alone (used by cumulative mode and the isolated runner)."""
    ids, MR, notes, fatal = _global_checks(run_dir)
    if fatal:
        return {}, notes
    prover = Prover(run_dir)
    flags = defaultdict(list)
    try:
        for idx in challenge_indices(MR, beacon, k, len(ids)):
            for reason in check_answer(ids[idx], prover.answer(ids[idx]), MR):
                flags[ids[idx].hex()].append(reason)
    finally:
        prover.close()
    return dict(flags), []


def verify_cumulative(run_dir: str | Path, k: int = 100, beacon: int = 0) -> Verdict:
    run_dir = Path(run_dir)
    t0 = time.perf_counter()
    s = structural_checks(run_dir)
    cf = None
    if not s.fatal and s.claimed == "COMPLETE":
        cf, _ = challenge_flags(run_dir, k, beacon)
    return combine(NAME, s, cf, t0)


def verify(run_dir: str | Path, keydir=None, k: int = 100, beacon: int = 0) -> Verdict:
    """Default entry point = cumulative (the fault-matrix mode)."""
    return verify_cumulative(run_dir, k, beacon)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--mode", choices=["cumulative", "sampling"], default="cumulative")
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--beacon", type=int, default=0)
    a = ap.parse_args()
    v = (verify_sampling(a.run, a.k, a.beacon) if a.mode == "sampling"
         else verify_cumulative(a.run, a.k, a.beacon))
    print(v.verdict, len(v.flagged), "flagged", v.notes)
