"""
RQ4 sweep — "why sampling does not transfer" (the two-column figure).

    python -m akm.run rq4 --out results/rq4                 # real (PREREG-gated)
    python -m akm.run rq4 --out results/rq4s --smoke --corpora 2 --beacons 5 --N 500
    python -m akm.run rq4-summary results/rq4/scores.csv

Design (Execution Plan §2.4, PREREG):
  V1-S only (mode = sampling), faults F1b, F3, F5, eps in {0.1 %, 1 %, 5 %},
  k in {1, 5, 10, 25, 50, 100, 200, 500},
  50 corpora x 20 beacons = 1,000 trials per (fault, eps, k) cell.

Efficiency (stated in the Methodology):
  * one migrated artifact per (corpus, fault, eps); F3 reuses the corpus's
    honest F0 artifact (post-hoc damage, no re-migration);
  * each beacon generates ONE sequence of 500 challenges; detection at a
    smaller k is the same sequence's first k. Each k is a valid sample, but
    points on one curve share challenges, so curves look smoother than
    independent samples would.
"""
from __future__ import annotations

import csv
import shutil
import time
from collections import defaultdict
from pathlib import Path

from .config import RunConfig
from .faults import apply_posthoc, choose_targets, migration_hooks, n_targets, write_manifest
from .inventory import build_inventory
from .merkle import build_bundle
from .migrate import migrate
from .provision import provision
from .schemas import SCORES_COLUMNS, append_rows
from .score import wilson
from .store import Store
from .verifiers.v1 import challenge_traces

K_LIST = (1, 5, 10, 25, 50, 100, 200, 500)
EPS_LIST = (0.001, 0.01, 0.05)
FAULTS = ("F1b", "F3", "F5")
SEED_BASE = 1000          # RQ4 corpora use seeds 1001.. so they never coincide with E1's 1..100


def _ids(run: Path) -> list[bytes]:
    s = Store(run / "store", readonly=True, need_payload=False)
    ids = s.iter_ids()
    s.close()
    return ids


def _rows_for(traces, targets_hex: set, meta: dict, fault: str, eps: float,
              trial0: int, global_fail: bool) -> list[dict]:
    rows = []
    for b, tr in enumerate(traces):
        for k in K_LIST:
            prefix = tr[:k]
            failed = {h for h, bad in prefix if bad}
            challenged_t = {h for h, _ in prefix if h in targets_hex}
            tp, fp = len(failed & targets_hex), len(failed - targets_hex)
            fn = len(challenged_t - failed)
            verdict = "FAIL" if (global_fail or failed) else "PASS"
            rows.append({**meta, "k": k, "fault": fault, "eps": eps, "verifier": "V1",
                         "mode": "sampling", "trial": trial0 + b, "verdict": verdict,
                         "tp": tp, "fp": fp, "fn": fn, "detected": int(verdict == "FAIL")})
    return rows


def run_corpus(c: int, args, out: Path) -> None:
    seed = SEED_BASE + c
    cfg = RunConfig(seed=seed, N=args.N, size=args.size, tau=128, k=max(K_LIST),
                    fsync_policy=args.fsync)
    work = out / "work" / f"c{c}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    pre = work / "pre"
    provision(cfg, pre, write_corpus=False)
    build_inventory(pre)
    ids = _ids(pre)
    beacons = [c * 1_000_000 + b for b in range(args.beacons)]
    meta = {"run_id": cfg.run_id, "seed": seed, "N": cfg.N, "size": cfg.size, "tau": cfg.tau}
    trial0 = (c - 1) * args.beacons + 1

    f0 = work / "F0"                         # honest artifact, reused for F3
    shutil.copytree(pre, f0)
    migrate(f0, fsync_policy=cfg.fsync_policy)
    build_bundle(f0)

    rows = []
    for eps in EPS_LIST:
        for fault in FAULTS:
            dest = work / f"{fault}-{eps}"
            targets = choose_targets(ids, seed, f"{fault}-eps{eps}", n_targets(fault, eps, len(ids)))
            if fault == "F3":
                shutil.copytree(f0, dest)
                apply_posthoc(dest, "F3", targets, seed)
            else:
                shutil.copytree(pre, dest)
                migrate(dest, hooks=migration_hooks(fault, targets, seed, len(ids)),
                        fsync_policy=cfg.fsync_policy)
                build_bundle(dest)
            write_manifest(dest, fault, eps, seed, targets)
            gfail, traces = challenge_traces(dest, beacons, max(K_LIST))
            if gfail:
                traces = [[] for _ in beacons]
            rows += _rows_for(traces, {t.hex() for t in targets}, meta, fault, eps, trial0, gfail)
            shutil.rmtree(dest)
    append_rows(out / "scores.csv", SCORES_COLUMNS, rows)
    shutil.rmtree(work)


def _drop_corpus_rows(csv_path: Path, seed: int) -> None:
    if not csv_path.exists():
        return
    with csv_path.open() as f:
        keep = [r for r in csv.DictReader(f) if int(r["seed"]) != seed]
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SCORES_COLUMNS)
        w.writeheader()
        w.writerows(keep)


def cmd_rq4(args) -> None:
    out = Path(args.out)
    done = out / "done"
    done.mkdir(parents=True, exist_ok=True)
    for c in range(1, args.corpora + 1):
        if (done / f"c{c}").exists():
            continue
        _drop_corpus_rows(out / "scores.csv", SEED_BASE + c)
        t = time.perf_counter()
        run_corpus(c, args, out)
        (done / f"c{c}").write_text("ok")
        print(f"corpus {c}/{args.corpora} done in {time.perf_counter() - t:.1f}s", flush=True)
    print("RQ4 sweep complete.", flush=True)


# ------------------------------------------------------------ summary -------
def theory(eps: float, N: int, k: int) -> float:
    """1 - (1 - m/N)^k with m = number of damaged records actually injected."""
    return 1 - (1 - max(1, round(eps * N)) / N) ** k


def rq4_cells(csv_path: str | Path):
    """Shared by rq4-summary and report. Returns (cells, N_of, fpfn):
    cells[(fault, eps, k)] = [detected, n]; fpfn[fault] = [innocent flags,
    challenged damaged records NOT flagged], counted at the longest k."""
    cells = defaultdict(lambda: [0, 0])
    N_of = {}
    fpfn = defaultdict(lambda: [0, 0])
    for r in csv.DictReader(open(csv_path)):
        key = (r["fault"], float(r["eps"]), int(r["k"]))
        cells[key][0] += int(r["detected"])
        cells[key][1] += 1
        N_of[key] = int(r["N"])
        if int(r["k"]) == max(K_LIST):          # the longest prefix contains all the others
            fpfn[r["fault"]][0] += int(r["fp"])
            fpfn[r["fault"]][1] += int(r["fn"])
    return cells, N_of, fpfn


def summarize(csv_path: str | Path, quiet: bool = False) -> dict:
    """Prints the table with 95 % Wilson CIs (for the figure) and applies the
    falsification rule with a BONFERRONI-adjusted interval (for the decision):
    48 F1b/F3 cells share challenge sequences, so ~5 % of 95 % CIs miss by
    chance even if the theory is exact. Bonferroni stays valid under that
    dependence: each cell is tested at alpha = 0.05 / 48 (about 99.9 %)."""
    from statistics import NormalDist
    cells, N_of, fpfn = rq4_cells(csv_path)
    misses, checked, f5_nonzero = [], 0, []
    lines = [f"{'fault':5s} {'eps':>6s} {'k':>4s} {'rate':>7s}  {'95% Wilson CI':>17s} {'theory':>7s}  in-CI"]
    for (fault, eps, k), (d, n) in sorted(cells.items()):
        th_val = theory(eps, N_of[(fault, eps, k)], k)
        lo, hi = wilson(d, n)
        if fault == "F5":
            ok = d == 0
            if not ok:
                f5_nonzero.append((eps, k, d))
            th = "0 (Cor 1.1)"
        else:
            checked += 1
            ok = lo <= th_val <= hi
            if not ok:
                misses.append((fault, eps, k))
            th = f"{th_val:7.3f}"
        lines.append(f"{fault:5s} {eps:6.3f} {k:4d} {d / n:7.3f}  [{lo:6.3f}, {hi:6.3f}] {th:>7s}  "
                     f"{'yes' if ok else 'NO'}")
    z_bonf = NormalDist().inv_cdf(1 - 0.05 / (2 * max(checked, 1)))
    bonf_misses = []
    for (fault, eps, k), (d, n) in sorted(cells.items()):
        if fault == "F5":
            continue
        th_val = theory(eps, N_of[(fault, eps, k)], k)
        lo, hi = wilson(d, n, z=z_bonf)
        if not lo <= th_val <= hi:
            bonf_misses.append((fault, eps, k))
    res = {"checked": checked, "misses": misses, "bonf_misses": bonf_misses,
           "f5_nonzero": f5_nonzero, "fpfn": dict(fpfn)}
    if not quiet:
        print("\n".join(lines))
        print(f"\nF1b/F3 cells outside their 95% CI: {len(misses)} of {checked} "
              f"(about {0.05 * checked:.1f} expected by chance even if the theory is exact)")
        print(f"F1b/F3 cells outside their Bonferroni-adjusted CI (z={z_bonf:.2f}): {len(bonf_misses)}")
        for f, (fp, fn) in sorted(fpfn.items()):
            print(f"  {f}: innocent records flagged = {fp}, challenged damaged records NOT flagged = {fn}")
        print(f"F5 cells with ANY detection: {len(f5_nonzero)}  (Corollary 1.1 predicts 0)")
        ok = not bonf_misses and not f5_nonzero
        print(f"\nP2 (with Bonferroni rule): {'PASS' if ok else 'FAIL'}")
    return res
