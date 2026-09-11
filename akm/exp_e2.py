"""
Experiment 2 — Cost (RQ2): what does climbing the ladder cost?

    python -m akm.run e2 --out results/e2                    # real (PREREG-gated)
    python -m akm.run e2 --out results/e2 --include-1m       # + the 10^6 x 200 B config
    python -m akm.run e2 --out results/e2s --smoke --Ns 300 --sizes 200 --reps 2
    python -m akm.run e2-summary results/e2

Grid: N in {10^3, 10^4, 10^5} x size in {200 B, 2 KB, 32 KB}  (+ optional 10^6 x 200 B)
Per configuration:
  migration, BOTH fsync policies (issue 8), two variants:
      "none"  = no-proof control (Algorithm 1 without receipts or bundle)
      "proof" = receipts + Merkle bundle — the migration that V0, V1, V2-minus
                and V2 all audit (the commitment is installed at provisioning,
                so these rungs need the identical migration)
  verification: V0, V1S (sampling, k=100), V2minus, V2 on the proof artifact
  timing hygiene: rep 0 = warm-up (discarded), reps 1..5 measured,
                  each measurement in a fresh process (akm/bench.py)
  storage: tuple / receipt / Merkle bytes per record from real counters,
           plus a tau sweep {64, 96, 128, 256} for the commitment column

Between reps the store is RESET (w_new cleared, epoch back to old, receipts
deleted) instead of re-copied: copying 3.3 GB six times per policy would
dominate the run. The first (warm-up) rep runs on the fresh store; reps 1-5
all run on a reset store, so they are measured under the same conditions.
"""
from __future__ import annotations

import csv
import json
import shutil
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from .config import RunConfig
from .inventory import build_inventory
from .merkle import build_bundle
from .migrate import migrate
from .provision import provision
from .schemas import STORAGE_COLUMNS, TIMINGS_COLUMNS, append_row
from .store import Store

DEFAULT_NS = (1_000, 10_000, 100_000)
DEFAULT_SIZES = (200, 2048, 32768)
TAUS = (64, 96, 128, 256)
VERIFIERS = ("V0", "V1S", "V2minus", "V2")
GROUP = "group:1000"


# ---------------------------------------------------------------- helpers ---
def reset_migration(run: str | Path) -> None:
    run = Path(run)
    s = Store(run / "store", need_payload=False)
    s.wraps.execute("UPDATE wraps SET w_new = NULL, epoch = 0")
    s.wraps.commit()
    s.close()
    for f in ("receipts.bin", "bundle.json", "merkle_nodes.bin"):
        (run / f).unlink(missing_ok=True)


def bench(*args: str) -> dict:
    p = subprocess.run([sys.executable, "-m", "akm.bench", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"bench {' '.join(args)} failed:\n{p.stderr[-2000:]}")
    r = json.loads(p.stdout.strip().splitlines()[-1])
    if not r["ok"]:
        raise RuntimeError(f"bench {' '.join(args)}: honest run did not succeed ({r})")
    return r


def need_bytes(N: int, size: int) -> int:
    """Rough disk estimate for one configuration (store + journal headroom)."""
    per = (size + 16) + 12 + 16 * 2 + 40 * 2 + 32 + 83 + 32 + 120   # fields + SQLite overhead
    return int(N * per * 1.5)


def storage_rows(run: Path, cfg: RunConfig, verifiers=("V0", "V1", "V2minus", "V2")) -> list[dict]:
    s = Store(run / "store", readonly=True)
    b = s.tuple_bytes_per_record()
    s.close()
    receipt = (run / "receipts.bin").stat().st_size / cfg.N
    merkle = (run / "merkle_nodes.bin").stat().st_size / cfg.N
    rows = []
    for v in verifiers:
        tup = b["cmt"] if v == "V2" else 0.0
        # Only V1 needs the STORED tree (the migrator answers challenges from it).
        # V0, V2-minus and V2 recompute the root from the receipt log themselves.
        mk = merkle if v == "V1" else 0.0
        total = tup + receipt + mk
        rows.append({"run_id": cfg.run_id, "N": cfg.N, "size": cfg.size, "tau": cfg.tau,
                     "verifier": v, "tuple_bytes_per_rec": round(tup, 3),
                     "receipt_bytes_per_rec": round(receipt, 3),
                     "merkle_bytes_per_rec": round(mk, 3),
                     "total_bytes_per_rec": round(total, 3),
                     "pct_payload": round(100 * total / cfg.size, 4),
                     "pct_tuple": round(100 * total / b["tuple_without_cmt"], 4)})
    return rows


def disk_info(path: Path) -> dict:
    info = {}
    try:
        src = subprocess.run(["findmnt", "-n", "-o", "SOURCE,FSTYPE", "--target", str(path)],
                             capture_output=True, text=True).stdout.strip()
        info["mount"] = src
        dev = src.split()[0].split("/")[-1].rstrip("0123456789")
        rot = Path(f"/sys/block/{dev}/queue/rotational")
        if rot.exists():
            info["rotational"] = rot.read_text().strip() == "1"
    except (OSError, IndexError):
        pass
    return info


# ---------------------------------------------------------------- driver ----
def run_config(N: int, size: int, args, out: Path) -> None:
    cfg = RunConfig(seed=1, N=N, size=size, tau=128)
    art = out / "work" / cfg.run_id
    shutil.rmtree(art, ignore_errors=True)
    art.parent.mkdir(parents=True, exist_ok=True)
    provision(cfg, art, write_corpus=False)
    build_inventory(art)
    policies = [GROUP] if (N >= 1_000_000 and not args.per_record_1m) else ["per_record", GROUP]
    tpath = out / "timings.csv"

    def trow(phase, verifier, policy, rep, r):
        append_row(tpath, TIMINGS_COLUMNS, {
            "run_id": cfg.run_id, "phase": phase, "verifier": verifier, "N": N, "size": size,
            "tau": cfg.tau, "fsync_policy": policy, "rep": rep, "wall_s": round(r["wall_s"], 6),
            "cpu_s": round(r["cpu_s"], 6), "peak_rss_mb": round(r["peak_rss_mb"], 2)})

    for pi, policy in enumerate(policies):
        for rep in range(args.reps + 1):              # rep 0 = warm-up, discarded
            reset_migration(art)
            r_none = bench("migrate", "--run", str(art), "--fsync", policy, "--proof", "none")
            reset_migration(art)
            r_proof = bench("migrate", "--run", str(art), "--fsync", policy, "--proof", "receipts")
            if rep > 0:
                trow("migrate", "none", policy, rep, r_none)
                trow("migrate", "proof", policy, rep, r_proof)
            if pi == 0:                   # verification is read-only: measured under one policy
                for v in VERIFIERS:       # rep 0 runs too, as the verifiers' own warm-up
                    rv = bench("verify", "--run", str(art), "--verifier", v if v != "V1S" else "V1")
                    if rep > 0:
                        trow("verify", v, "-", rep, rv)
    for row in storage_rows(art, cfg):
        append_row(out / "storage.csv", STORAGE_COLUMNS, row)
    shutil.rmtree(art)


def run_tau_sweep(args, out: Path) -> None:
    """Commitment column across tau (storage only; no timing)."""
    N = 10_000 if 10_000 in args.Ns else args.Ns[0]
    for size in args.sizes:
        for tau in TAUS:
            if tau == 128:
                continue                          # already written by the main grid
            cfg = RunConfig(seed=1, N=N, size=size, tau=tau)
            art = out / "work" / cfg.run_id
            shutil.rmtree(art, ignore_errors=True)
            provision(cfg, art, write_corpus=False)
            build_inventory(art)
            migrate(art, fsync_policy=GROUP)
            build_bundle(art)
            for row in storage_rows(art, cfg, verifiers=("V2",)):
                append_row(out / "storage.csv", STORAGE_COLUMNS, row)
            shutil.rmtree(art)


def _drop_rows(path: Path, columns: list[str], run_id: str) -> None:
    if not path.exists():
        return
    with path.open() as f:
        keep = [r for r in csv.DictReader(f) if r["run_id"] != run_id]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(keep)


def cmd_e2(args) -> None:
    out = Path(args.out)
    done = out / "done"
    done.mkdir(parents=True, exist_ok=True)
    env_path = out / "environment.json"
    if env_path.exists():
        env = json.loads(env_path.read_text())
        env["disk"] = disk_info(out)
        env_path.write_text(json.dumps(env, indent=2))
    configs = [(N, s) for N in args.Ns for s in args.sizes]
    if args.include_1m:
        configs.append((1_000_000, 200))
    for N, size in configs:
        label = f"N{N}-b{size}"
        if (done / label).exists():
            continue
        free = shutil.disk_usage(out).free
        if free < need_bytes(N, size):
            print(f"SKIPPING {label}: needs ~{need_bytes(N, size) / 1e9:.1f} GB, "
                  f"only {free / 1e9:.1f} GB free", flush=True)
            continue
        rid = RunConfig(seed=1, N=N, size=size, tau=128).run_id
        _drop_rows(out / "timings.csv", TIMINGS_COLUMNS, rid)
        _drop_rows(out / "storage.csv", STORAGE_COLUMNS, rid)
        t = time.perf_counter()
        run_config(N, size, args, out)
        (done / label).write_text("ok")
        print(f"{label} done in {time.perf_counter() - t:.1f}s", flush=True)
    if not (done / "tau-sweep").exists():
        run_tau_sweep(args, out)
        (done / "tau-sweep").write_text("ok")
        print("tau sweep done", flush=True)
    print("Experiment 2 complete.", flush=True)


# --------------------------------------------------------------- summary ----
def _med_iqr(xs):
    xs = sorted(xs)
    if len(xs) < 2:
        return xs[0], 0.0
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return statistics.median(xs), q[2] - q[0]


def summarize(out_dir: str | Path, quiet: bool = False) -> dict:
    out = Path(out_dir)
    t = defaultdict(lambda: {"wall_s": [], "cpu_s": []})
    for r in csv.DictReader(open(out / "timings.csv")):
        key = (int(r["N"]), int(r["size"]), r["phase"], r["verifier"], r["fsync_policy"])
        t[key]["wall_s"].append(float(r["wall_s"]))
        t[key]["cpu_s"].append(float(r["cpu_s"]))
    configs = sorted({(k[0], k[1]) for k in t})
    p4 = []
    lines = []
    for N, size in configs:
        lines.append(f"\nN={N:,}  size={size} B")
        for pol in ("per_record", GROUP):
            for var in ("none", "proof"):
                k = (N, size, "migrate", var, pol)
                if k in t:
                    m, iqr = _med_iqr(t[k]["wall_s"])
                    lines.append(f"  migrate {var:5s} {pol:11s} wall {m:9.3f} s (IQR {iqr:.3f})"
                                 f"  cpu {statistics.median(t[k]['cpu_s']):8.3f} s")
        for v in VERIFIERS:
            k = (N, size, "verify", v, "-")
            if k in t:
                m, iqr = _med_iqr(t[k]["wall_s"])
                lines.append(f"  verify  {v:7s}             wall {m:9.3f} s (IQR {iqr:.3f})"
                             f"  cpu {statistics.median(t[k]['cpu_s']):8.3f} s")
        v2 = t.get((N, size, "verify", "V2", "-"))
        for pol in ("per_record", GROUP):
            mig = t.get((N, size, "migrate", "proof", pol))
            if v2 and mig:
                for basis in ("wall_s", "cpu_s"):
                    ratio = statistics.median(v2[basis]) / statistics.median(mig[basis])
                    p4.append((N, size, pol, basis, ratio))
                    lines.append(f"  P4 ratio V2/migrate [{pol}, {basis[:-2]}] = {ratio:.3f} "
                                 f"{'< 0.10' if ratio < 0.10 else '>= 0.10  (P4 fails here)'}")
    # storage + P7
    st = list(csv.DictReader(open(out / "storage.csv")))
    p7_fail = [r for r in st if r["verifier"] == "V2" and int(r["tau"]) <= 128
               and float(r["receipt_bytes_per_rec"]) <= int(r["tau"]) / 8]
    lines.append("\nStorage (bytes/record):  verifier  tau  tuple  receipt  merkle  total  %payload")
    for r in st:
        lines.append(f"  N={int(r['N']):>7,} b={int(r['size']):>5}  {r['verifier']:7s} {r['tau']:>4}"
                     f" {float(r['tuple_bytes_per_rec']):6.1f} {float(r['receipt_bytes_per_rec']):8.1f}"
                     f" {float(r['merkle_bytes_per_rec']):7.1f} {float(r['total_bytes_per_rec']):6.1f}"
                     f" {float(r['pct_payload']):8.2f}")
    lines.append(f"\nP7 (receipt log > commitment at every tau <= 128): "
                 f"{'PASS' if not p7_fail else 'FAIL on ' + str(len(p7_fail)) + ' rows'}")
    if not quiet:
        print("\n".join(lines))
    return {"p4": p4, "p7_fail": p7_fail}
