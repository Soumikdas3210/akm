"""
Shared aggregation for Experiment 1, used by BOTH `summarize` and `report`,
so the numbers printed at the terminal and the numbers in the paper's tables
come from one function and can never disagree.
"""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

E1_ORDER = ["F0", "F1a", "F1b", "F2", "F3", "F4r", "F4m", "F5", "F5b", "F5c", "F6", "F7"]
VERIFIERS = ["V0", "V1", "V2minus", "V2", "V3"]


def e1_aggregate(csv_path: str | Path) -> dict:
    cells = defaultdict(lambda: [0, 0])          # (label, verifier) -> [detected, n]
    fp = defaultdict(lambda: [0, 0])             # verifier -> [F0 FAILs, F0 trials]
    for r in csv.DictReader(open(csv_path)):
        label = r["fault"] + (f"@{float(r['eps']):g}" if float(r["eps"]) else "")
        cells[(label, r["verifier"])][0] += int(r["detected"])
        cells[(label, r["verifier"])][1] += 1
        if r["fault"] == "F0":
            fp[r["verifier"]][0] += int(r["verdict"] == "FAIL")
            fp[r["verifier"]][1] += 1
    labels = sorted({k[0] for k in cells},
                    key=lambda s: (E1_ORDER.index(s.split("@")[0]),
                                   float(s.split("@")[1]) if "@" in s else 0.0))
    return {"cells": dict(cells), "fp": dict(fp), "labels": labels}


def e1_rate(agg: dict, label: str, verifier: str):
    d, n = agg["cells"].get((label, verifier), (0, 0))
    return d / n if n else None


def e1_gate2(agg: dict) -> dict[str, bool]:
    labels, fp = agg["labels"], agg["fp"]
    f5 = [l for l in labels if l.startswith("F5")]
    r = lambda l, v: e1_rate(agg, l, v)
    return {
        "F0: zero false positives everywhere": all(a == 0 for a, _ in fp.values()),
        "V0 and V1 read 0% on F5, F5b, F5c": all(r(l, v) == 0 for l in f5 for v in ("V0", "V1")),
        "V2 and V2minus read 100% on F5, F5b, F5c": all(r(l, v) == 1 for l in f5 for v in ("V2", "V2minus")),
        "F7: V2minus 0%, V2 100%": r("F7", "V2minus") == 0 and r("F7", "V2") == 1,
        "No row other than F7 separates V2minus from V2 (P6)":
            all(r(l, "V2") == r(l, "V2minus") for l in labels if l not in ("F0", "F7")),
    }
