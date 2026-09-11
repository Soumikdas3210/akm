"""
Reproducibility check: does a re-run give byte-identical detection results?

    python -m akm.run repro-check results/e1/scores.csv ~/akm-repro/results/e1/scores.csv

Every row in the NEW file must exist in the ORIGINAL file (same seed, fault,
eps, verifier, mode, k, trial) with every column identical. scores.csv holds
no timing fields, so nothing is excluded: verdicts and tp/fp/fn must match.
Works for E1 and RQ4 files alike (same schema).

Exit code 0 = reproduced; 1 = mismatches, rows missing from the original, or
nothing compared.
"""
from __future__ import annotations

import csv
from pathlib import Path

KEY = ("seed", "fault", "eps", "verifier", "mode", "k", "trial")


def _load(path: Path) -> dict:
    out = {}
    for r in csv.DictReader(open(path)):
        k = tuple(r[c] for c in KEY)
        if k in out:
            raise ValueError(f"duplicate row {k} in {path}")
        out[k] = r
    return out


def repro_check(orig: str | Path, new: str | Path, quiet: bool = False) -> dict:
    a, b = _load(Path(orig)), _load(Path(new))
    compared, mismatches, missing = 0, [], []
    for k, row in b.items():
        if k not in a:
            missing.append(k)
            continue
        compared += 1
        diffs = {c: (a[k][c], row[c]) for c in row if a[k].get(c) != row[c]}
        if diffs:
            mismatches.append((k, diffs))
    ok = compared > 0 and not mismatches and not missing
    if not quiet:
        seeds = sorted({k[0] for k in b}, key=int)
        print(f"compared {compared} rows (seeds {', '.join(seeds[:10])}{'…' if len(seeds) > 10 else ''})")
        print(f"mismatched rows: {len(mismatches)}   rows missing from original: {len(missing)}")
        for k, d in mismatches[:5]:
            print(f"  MISMATCH {dict(zip(KEY, k))}: {d}")
        for k in missing[:5]:
            print(f"  NOT IN ORIGINAL {dict(zip(KEY, k))}")
        print("REPRODUCED: identical detection results" if ok else "NOT REPRODUCED")
    return {"ok": ok, "compared": compared, "mismatches": mismatches, "missing": missing}
