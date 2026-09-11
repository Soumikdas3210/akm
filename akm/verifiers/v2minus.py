"""
V2⁻ — the two-key inspector. Holds K_old AND K_new. Never plaintext.

Structural layer (no keys)  +  key layer:
    for every record that has a new wrap:
        DEK_a = Unwrap(K_old, w_old),  DEK_b = Unwrap(K_new, w_new)
        flag if they differ (constant-time compare)

KEY-LAYER ISOLATION (Execution Plan issue 3): key_layer() opens wraps.db
ONLY (need_payload=False). It never has C_i, so holding keys never lets it
decrypt a record. Day 2 moves it into its own Docker container.

F7: if K_old has been retired (file absent), V2⁻ cannot run at all.
"""
from __future__ import annotations

import argparse
import hmac
import time
from pathlib import Path

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from ..provision import unwrap
from ..store import Store
from .common import UNRUNNABLE, Verdict, combine, structural_checks

NAME = "V2minus"


def key_layer(store_dir: Path, k_old: bytes, k_new: bytes) -> dict:
    flags: dict = {}
    s = Store(store_dir, readonly=True, need_payload=False)   # <- wraps.db only
    try:
        for rid, w_old, w_new, _cmt in s.iter_new_wraps():
            h = rid.hex()
            if w_old is None:
                flags.setdefault(h, []).append("old wrap deleted: cannot compare")
                continue
            try:
                dek_old = unwrap(k_old, w_old)
            except InvalidUnwrap:
                flags.setdefault(h, []).append("old wrap does not unwrap under K_old")
                continue
            try:
                dek_new = unwrap(k_new, w_new)
            except InvalidUnwrap:
                flags.setdefault(h, []).append("new wrap does not unwrap under K_new")
                continue
            if not hmac.compare_digest(dek_old, dek_new):
                flags.setdefault(h, []).append("new wrap holds a DIFFERENT DEK (wrong rewrap)")
    finally:
        s.close()
    return flags


def verify(run_dir: str | Path, keydir: str | Path | None = None) -> Verdict:
    run_dir = Path(run_dir)
    keydir = Path(keydir) if keydir else run_dir / "keys"
    t0 = time.perf_counter()
    if not (keydir / "kek_old.bin").exists() or not (keydir / "kek_new.bin").exists():
        return Verdict(NAME, UNRUNNABLE, notes=["K_old retired or K_new missing: audit cannot run (F7)"],
                       wall_s=time.perf_counter() - t0)
    s = structural_checks(run_dir)
    kf = None if s.fatal else key_layer(
        run_dir / "store", (keydir / "kek_old.bin").read_bytes(), (keydir / "kek_new.bin").read_bytes())
    return combine(NAME, s, kf, t0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--keys", default=None)
    a = ap.parse_args()
    v = verify(a.run, a.keys)
    print(v.verdict, len(v.flagged), "flagged", v.notes)
