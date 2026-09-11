"""
End-to-end driver: P0 -> P1/P2 -> P3 -> P4 -> P6 -> P7, in the order of Figure 1.

    python -m akm.pipeline --seed 1 --N 1000 --size 200 --tau 128 --out runs/demo

Run with no faults this is the HONEST run. Rule (Execution Plan §2.3):
every verifier must PASS honest runs on >= 10 seeds before any fault is
injected. `--seeds 10` does exactly that check.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from .config import RunConfig
from .inventory import build_inventory
from .merkle import build_bundle
from .migrate import Hooks, migrate
from .provision import provision
from .verifiers import v0, v2, v2minus, v3

VERIFIERS = {"V0": v0.verify, "V2minus": v2minus.verify, "V2": v2.verify, "V3": v3.verify}


def build(cfg: RunConfig, run_dir: str | Path, hooks: Hooks | None = None,
          fsync_policy: str | None = None) -> dict:
    """P0-P6 for one run. Returns the migration stats."""
    run_dir = Path(run_dir)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    provision(cfg, run_dir)          # P0 + P1 + P2
    build_inventory(run_dir)         # P3: anchor signs the id list BEFORE migration
    stats = migrate(run_dir, hooks=hooks, fsync_policy=fsync_policy)   # P4 (+P5 hooks)
    build_bundle(run_dir, claimed="COMPLETE")                          # P6
    return stats


def verify_all(run_dir: str | Path, keydir: str | Path | None = None) -> dict:
    """P7: every verifier against the same artifact (one migration, many verdicts)."""
    out = {}
    for name, fn in VERIFIERS.items():
        v = fn(run_dir, keydir)
        v.save(run_dir)
        out[name] = v
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="honest end-to-end run")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--seeds", type=int, default=1, help="run this many consecutive seeds")
    ap.add_argument("--N", type=int, default=1000)
    ap.add_argument("--size", type=int, default=200)
    ap.add_argument("--tau", type=int, default=128)
    ap.add_argument("--fsync", default="per_record")
    ap.add_argument("--out", default="runs/honest")
    a = ap.parse_args()

    all_pass = True
    for seed in range(a.seed, a.seed + a.seeds):
        cfg = RunConfig(seed=seed, N=a.N, size=a.size, tau=a.tau, fsync_policy=a.fsync)
        run_dir = Path(a.out) / cfg.run_id
        st = build(cfg, run_dir)
        verdicts = verify_all(run_dir)
        line = "  ".join(f"{n}={v.verdict}" for n, v in verdicts.items())
        print(f"{cfg.run_id}: migrated {st['migrated']} in {st['wall_s']:.2f}s  |  {line}")
        all_pass &= all(v.verdict == "PASS" for v in verdicts.values())
    print("ALL PASS" if all_pass else "SOME VERIFIER DID NOT PASS - investigate before injecting faults")


if __name__ == "__main__":
    main()
