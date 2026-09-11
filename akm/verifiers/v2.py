"""
V2 — the fingerprint (commitment) inspector. Holds K_new ONLY.

Structural layer (no keys)  +  key layer:
    for every record that has a new wrap:
        DEK' = Unwrap(K_new, w_new)
        flag if Trunc_tau(H("AKM-cmt-v1" || DEK' || id)) != cmt

Uses provision.commitment() — the single definition of the formula — so
V2 cannot silently drift from what provisioning stored.
Key layer opens wraps.db only (issue 3). Still runs after K_old is gone (F7).
"""
from __future__ import annotations

import argparse
import hmac
import time
from pathlib import Path

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from ..provision import commitment, unwrap
from ..store import Store
from .common import UNRUNNABLE, Verdict, combine, structural_checks

NAME = "V2"


def key_layer(store_dir: Path, k_new: bytes, tau: int) -> dict:
    flags: dict = {}
    s = Store(store_dir, readonly=True, need_payload=False)   # <- wraps.db only
    try:
        for rid, _w_old, w_new, cmt in s.iter_new_wraps():
            h = rid.hex()
            try:
                dek = unwrap(k_new, w_new)
            except InvalidUnwrap:
                flags.setdefault(h, []).append("new wrap does not unwrap under K_new")
                continue
            if not hmac.compare_digest(commitment(dek, rid, tau), cmt):
                flags.setdefault(h, []).append("commitment mismatch (wrong DEK in new wrap)")
    finally:
        s.close()
    return flags


def verify(run_dir: str | Path, keydir: str | Path | None = None) -> Verdict:
    run_dir = Path(run_dir)
    keydir = Path(keydir) if keydir else run_dir / "keys"
    t0 = time.perf_counter()
    if not (keydir / "kek_new.bin").exists():
        return Verdict(NAME, UNRUNNABLE, notes=["K_new missing"], wall_s=time.perf_counter() - t0)
    s = structural_checks(run_dir)
    kf = None if s.fatal else key_layer(run_dir / "store", (keydir / "kek_new.bin").read_bytes(), s.tau)
    return combine(NAME, s, kf, t0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--keys", default=None)
    a = ap.parse_args()
    v = verify(a.run, a.keys)
    print(v.verdict, len(v.flagged), "flagged", v.notes)
