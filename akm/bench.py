"""
Measure ONE phase in a fresh process and print a JSON line.

    python -m akm.bench migrate --run DIR --fsync per_record --proof receipts
    python -m akm.bench migrate --run DIR --fsync group:1000 --proof none
    python -m akm.bench verify  --run DIR --verifier V2

Why a fresh process per measurement: peak memory (ru_maxrss) can only go UP
during a process's life, so measuring several phases in one process would
report the largest of them for all. A new process gives each phase its own
peak. Timing is taken INSIDE the process, so interpreter start-up is excluded.

Reported:
  wall_s       time.perf_counter() around the phase
  cpu_s        user + system CPU of this process during the phase
  peak_rss_mb  peak resident memory of the process (includes the ~30-40 MB
               Python + cryptography baseline; stated in the Methodology)
"""
from __future__ import annotations

import argparse
import json
import resource
import time


def _cpu() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["migrate", "verify"])
    ap.add_argument("--run", required=True)
    ap.add_argument("--fsync", default="per_record")
    ap.add_argument("--proof", choices=["none", "receipts"], default="receipts")
    ap.add_argument("--verifier", choices=["V0", "V1", "V2minus", "V2"], default="V0")
    ap.add_argument("--k", type=int, default=100)
    a = ap.parse_args()

    # import everything BEFORE starting the clock
    from .merkle import build_bundle
    from .migrate import migrate
    from .verifiers import v0, v1, v2, v2minus

    c0, t0 = _cpu(), time.perf_counter()
    if a.phase == "migrate":
        st = migrate(a.run, fsync_policy=a.fsync, emit_receipts=(a.proof == "receipts"))
        if a.proof == "receipts":
            build_bundle(a.run)                      # proof assembly is part of the cost
        ok = st["migrated"] > 0
        verdict = None
    else:
        fn = {"V0": v0.verify, "V2minus": v2minus.verify, "V2": v2.verify,
              "V1": lambda r: v1.verify_sampling(r, a.k, beacon=0)}[a.verifier]
        v = fn(a.run)
        verdict = v.verdict
        ok = verdict == "PASS"
    wall, cpu = time.perf_counter() - t0, _cpu() - c0
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024   # Linux: KB
    print(json.dumps({"wall_s": wall, "cpu_s": cpu, "peak_rss_mb": peak_mb,
                      "ok": ok, "verdict": verdict}))


if __name__ == "__main__":
    main()
