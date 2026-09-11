"""
V0 — the paperwork inspector. Holds NO keys.

It is exactly common.structural_checks(): signed inventory, signed Merkle
root, receipt set vs inventory, every receipt vs the bytes in storage.
Built to DEMONSTRATE its failure on F5, not to propose it.
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from .common import combine, structural_checks


def verify(run_dir: str | Path, keydir: str | Path | None = None):
    t0 = time.perf_counter()
    s = structural_checks(run_dir)
    return combine("V0", s, None, t0)          # no key layer: V0 has nothing to add


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    v = verify(ap.parse_args().run)
    print(v.verdict, len(v.flagged), "flagged", v.notes)
