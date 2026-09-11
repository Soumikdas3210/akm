"""
Experiment driver.

    python -m akm.run e1 --seeds 1-100 --out results/e1          # the real thing
    python -m akm.run e1 --seeds 1-3 --out results/smoke --smoke  # smoke test
    python -m akm.run summarize results/e1/scores.csv            # matrix + gate 2
    python -m akm.run rq4 ... / rq4-summary ...                  # see akm/exp_rq4.py
    python -m akm.run e2  ... / e2-summary  ...                  # see akm/exp_e2.py
    python -m akm.run report / freeze / repro-check              # Day 4 tools
    python -m akm.run draft / demo                               # Day 5: paper drafts, live demo

Safety rules built in (Execution Plan §2.3):
  * A real (non --smoke) E1 run REFUSES to start unless PREREG.md is committed
    in git. The commit hash is recorded in environment.json.
  * Verifiers run isolated (akm/isolated.py); the manifest lives in private/.
  * V3 is cross-checked against the manifest; a conflict STOPS the run.
  * Resumable: finished seeds are marked in done/; rerunning skips them, and
    a half-finished seed has its partial rows removed before it is redone.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from .config import RunConfig
from .faults import (apply_posthoc, choose_targets, flipped_set, migration_hooks,
                     n_targets, write_manifest)
from .inventory import build_inventory
from .isolated import verify_isolated
from .keys_stage import stage_keys
from .merkle import build_bundle
from .migrate import SimulatedCrash, migrate
from .provision import provision
from .schemas import SCORES_COLUMNS
from .score import GroundTruthConflict, score_trial
from .store import Store

E1_ROWS = [("F0", 0.0), ("F1a", 0.0), ("F1b", 0.0), ("F2", 0.0), ("F3", 0.0), ("F4r", 0.0),
           ("F4m", 0.0), ("F5", 0.0), ("F5", 0.05), ("F5b", 0.0), ("F5c", 0.0), ("F6", 0.0),
           ("F7", 0.0)]


# ------------------------------------------------------------ environment ---
def prereg_commit() -> str | None:
    try:
        h = subprocess.run(["git", "log", "-n", "1", "--format=%H", "--", "PREREG.md"],
                           capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "PREREG.md"],
                               capture_output=True, text=True).stdout.strip()
        return h if h and not dirty else None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def code_commit() -> tuple[str | None, bool]:
    """(HEAD commit, True if the code has uncommitted changes)."""
    try:
        h = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                           check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "akm", "tests",
                                     "requirements.txt"], capture_output=True, text=True).stdout.strip())
        return h, dirty
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None, False


def environment(args, prereg: str | None) -> dict:
    import cryptography
    cpu = platform.processor()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    commit, dirty = code_commit()
    return {"prereg_commit": prereg, "code_commit": commit, "code_dirty": dirty,
            "smoke": args.smoke, "python": sys.version.split()[0],
            "cryptography": cryptography.__version__, "os": platform.platform(), "cpu": cpu,
            "experiment": args.cmd,
            "args": {k: v for k, v in vars(args).items() if k != "cmd"},
            "started": time.strftime("%Y-%m-%d %H:%M:%S")}


# ---------------------------------------------------------- artifact makers --
def _ids(run: Path) -> list[bytes]:
    s = Store(run / "store", readonly=True, need_payload=False)
    ids = s.iter_ids()
    s.close()
    return ids


def make_migrated(pre: Path, dest: Path, fault: str, eps: float, seed: int, fsync: str) -> dict:
    """Copy the provisioned corpus, migrate with the fault's hooks, bundle, manifest."""
    shutil.copytree(pre, dest)
    ids = _ids(dest)
    targets = choose_targets(ids, seed, fault, n_targets(fault, eps, len(ids)))
    hooks = migration_hooks(fault, targets, seed, len(ids))
    extra = {}
    if fault == "F6":
        try:
            migrate(dest, hooks=hooks, fsync_policy="per_record")   # F6 always per-record
            raise RuntimeError("F6 crash hook did not fire")
        except SimulatedCrash:
            pass
        build_bundle(dest, claimed="PARTIAL")
        extra["expected_flipped"] = flipped_set(dest)
    else:
        migrate(dest, hooks=hooks, fsync_policy=fsync)
        build_bundle(dest, claimed="COMPLETE")
    stage_keys(dest)
    write_manifest(dest, fault, eps, seed, targets, **extra)
    return json.loads((dest / "private" / "fault_manifest.json").read_text())


def make_posthoc(f0: Path, dest: Path, fault: str, seed: int) -> dict:
    shutil.copytree(f0, dest, ignore=shutil.ignore_patterns("verdict_*", "layers", "private"))
    ids = _ids(dest)
    targets = choose_targets(ids, seed, fault, n_targets(fault, 0.0, len(ids)))
    details = apply_posthoc(dest, fault, targets, seed)
    write_manifest(dest, fault, 0.0, seed, targets, **details)
    return json.loads((dest / "private" / "fault_manifest.json").read_text())


def _archive(src: Path, audit: Path, label: str) -> None:
    d = audit / label
    d.mkdir(parents=True, exist_ok=True)
    for f in list(src.glob("verdict_*.json")) + list((src / "private").glob("*.json")):
        shutil.copy(f, d / f.name)


# ------------------------------------------------------------------ E1 ------
def _drop_seed_rows(csv_path: Path, seed: int) -> None:
    if not csv_path.exists():
        return
    with csv_path.open() as f:
        rows = [r for r in csv.DictReader(f) if int(r["seed"]) != seed]
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SCORES_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def run_seed(seed: int, args, out: Path) -> None:
    cfg = RunConfig(seed=seed, N=args.N, size=args.size, tau=args.tau, k=args.k,
                    fsync_policy=args.fsync)
    work, audit = out / "work" / f"s{seed}", out / "audit" / f"s{seed}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    pre = work / "pre"
    provision(cfg, pre)                    # P0-P2
    build_inventory(pre)                   # P3
    meta = {"run_id": cfg.run_id, "seed": seed, "N": cfg.N, "size": cfg.size,
            "tau": cfg.tau, "k": cfg.k, "trial": seed}
    csv_path = out / "scores.csv"

    def evaluate(run: Path, manifest: dict, label: str, keyset="normal", verifiers=None):
        vs = verify_isolated(run, keyset=keyset, k=cfg.k, beacon=seed,
                             verifiers=verifiers or ("V0", "V1", "V2minus", "V2", "V3"))
        score_trial(csv_path, meta, manifest, vs, v3=vs.get("V3"))
        _archive(run, audit, label)

    f0 = work / "F0"
    m0 = make_migrated(pre, f0, "F0", 0.0, seed, cfg.fsync_policy)
    evaluate(f0, m0, "F0")
    f5_dir, f5_manifest = None, None
    for fault, eps in E1_ROWS:
        label = f"{fault}" + (f"-eps{eps}" if eps else "")
        if fault in ("F0", "F7"):
            continue
        dest = work / label
        if fault in ("F3", "F4r", "F4m"):
            m = make_posthoc(f0, dest, fault, seed)
        else:
            m = make_migrated(pre, dest, fault, eps, seed, cfg.fsync_policy)
        evaluate(dest, m, label)
        if fault == "F5" and eps == 0.0:
            f5_dir, f5_manifest = dest, m            # reused for F7
        elif fault not in ("F0",):
            shutil.rmtree(dest)
    # F7: the F5 artifact audited after K_old is retired (V2minus and V2 only)
    m7 = dict(f5_manifest, fault="F7", injection="verify:K_old-retired")
    (f5_dir / "private" / "fault_manifest_F7.json").write_text(json.dumps(m7, indent=2))
    evaluate(f5_dir, m7, "F7", keyset="f7", verifiers=("V2minus", "V2"))
    shutil.rmtree(work)                        # keep audit/, drop the big artifacts


def gate(args) -> Path:
    """Every real experiment run requires a committed, unmodified PREREG.md."""
    out = Path(args.out)
    prereg = prereg_commit()
    if not args.smoke and prereg is None:
        sys.exit("REFUSING TO RUN: PREREG.md is missing, uncommitted, or modified.\n"
                 "Commit it first (Execution Plan §2.3), or use --smoke for a labelled test run.")
    out.mkdir(parents=True, exist_ok=True)
    (out / "environment.json").write_text(json.dumps(environment(args, prereg), indent=2))
    return out


def cmd_e1(args) -> None:
    out = gate(args)
    lo, hi = (int(x) for x in args.seeds.split("-"))
    done = out / "done"
    done.mkdir(exist_ok=True)
    for seed in range(lo, hi + 1):
        if (done / f"s{seed}").exists():
            continue
        _drop_seed_rows(out / "scores.csv", seed)
        t = time.perf_counter()
        try:
            run_seed(seed, args, out)
        except GroundTruthConflict as e:
            print(f"STOPPED — ground-truth conflict (harness or V3 bug): {e}", flush=True)
            sys.exit(2)
        (done / f"s{seed}").write_text("ok")
        print(f"seed {seed} done in {time.perf_counter() - t:.1f}s", flush=True)
    print("Experiment 1 complete.", flush=True)


# ------------------------------------------------------------ summarize -----
def cmd_summarize(args) -> None:
    from .analysis import VERIFIERS, e1_aggregate, e1_gate2
    agg = e1_aggregate(args.csv)
    print(f"{'fault':10s}" + "".join(f"{v:>10s}" for v in VERIFIERS))
    for lab in agg["labels"]:
        line = f"{lab:10s}"
        for v in VERIFIERS:
            d, n = agg["cells"].get((lab, v), (0, 0))
            if lab == "F0":
                a, m = agg["fp"].get(v, (0, 0))
                line += f"{f'FP {a}/{m}':>10s}" if m else f"{'n/a':>10s}"
            else:
                line += f"{f'{100 * d / n:.0f}%':>10s}" if n else f"{'n/a':>10s}"
        print(line)
    print("\nQuality gate 2:")
    for name, ok in e1_gate2(agg).items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e1 = sub.add_parser("e1")
    e1.add_argument("--seeds", default="1-100")
    e1.add_argument("--out", default="results/e1")
    e1.add_argument("--N", type=int, default=10_000)
    e1.add_argument("--size", type=int, default=2048)
    e1.add_argument("--tau", type=int, default=128)
    e1.add_argument("--k", type=int, default=100)
    e1.add_argument("--fsync", default="per_record")
    e1.add_argument("--smoke", action="store_true")
    sm = sub.add_parser("summarize")
    sm.add_argument("csv")

    r4 = sub.add_parser("rq4")
    r4.add_argument("--out", default="results/rq4")
    r4.add_argument("--corpora", type=int, default=50)
    r4.add_argument("--beacons", type=int, default=20)
    r4.add_argument("--N", type=int, default=10_000)
    r4.add_argument("--size", type=int, default=200)
    r4.add_argument("--fsync", default="per_record")
    r4.add_argument("--smoke", action="store_true")
    r4s = sub.add_parser("rq4-summary")
    r4s.add_argument("csv")

    e2 = sub.add_parser("e2")
    e2.add_argument("--out", default="results/e2")
    e2.add_argument("--Ns", default="1000,10000,100000")
    e2.add_argument("--sizes", default="200,2048,32768")
    e2.add_argument("--reps", type=int, default=5)
    e2.add_argument("--include-1m", action="store_true")
    e2.add_argument("--per-record-1m", action="store_true",
                    help="also run the 10^6 config with per-record fsync (many hours)")
    e2.add_argument("--smoke", action="store_true")
    e2s = sub.add_parser("e2-summary")
    e2s.add_argument("out")

    rc = sub.add_parser("repro-check")
    rc.add_argument("orig")
    rc.add_argument("new")
    rp = sub.add_parser("report")
    rp.add_argument("--results", default="results")
    fz = sub.add_parser("freeze")
    fz.add_argument("--results", default="results")
    fz.add_argument("--verify", action="store_true")
    fz.add_argument("--allow-dirty", action="store_true")
    fz.add_argument("--smoke", action="store_true")

    dr = sub.add_parser("draft")
    dr.add_argument("--results", default="results")
    dm = sub.add_parser("demo")
    dm.add_argument("--N", type=int, default=1000)
    dm.add_argument("--fast", action="store_true", help="no pauses between steps")
    dm.add_argument("--keep", action="store_true", help="keep the demo artifacts for inspection")

    a = ap.parse_args()
    if a.cmd == "draft":
        from .draft import build_draft, undefined_macros
        out = build_draft(a.results)
        missing = undefined_macros(out)
        print(f"wrote {out}/ (numbers.tex, setup.tex, results.tex, threats.tex, main.tex, tables/)")
        if missing:
            sys.exit(f"ERROR: undefined macros {sorted(missing)}")
        return
    if a.cmd == "demo":
        from .demo import run_demo
        run_demo(a.N, pause=0 if a.fast else 0.6, keep=a.keep)
        return
    if a.cmd == "repro-check":
        from .repro import repro_check
        sys.exit(0 if repro_check(a.orig, a.new)["ok"] else 1)
    if a.cmd == "report":
        from .report import build_report
        print("wrote", build_report(a.results))
        return
    if a.cmd == "freeze":
        from . import freeze as fr
        if a.verify:
            sys.exit(0 if fr.verify(a.results) else 1)
        fr.freeze(a.results, allow_dirty=a.allow_dirty, smoke=a.smoke)
        return
    if a.cmd == "e2":
        a.Ns = [int(x) for x in a.Ns.split(",")]
        a.sizes = [int(x) for x in a.sizes.split(",")]
    from . import exp_e2, exp_rq4
    {"e1": cmd_e1, "summarize": cmd_summarize,
     "rq4": lambda x: (gate(x), exp_rq4.cmd_rq4(x)),
     "rq4-summary": lambda x: exp_rq4.summarize(x.csv),
     "e2": lambda x: (gate(x), exp_e2.cmd_e2(x)),
     "e2-summary": lambda x: exp_e2.summarize(x.out)}[a.cmd](a)


if __name__ == "__main__":
    main()
