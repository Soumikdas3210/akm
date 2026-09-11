"""
V3 — the oracle. Holds EVERYTHING: K_old, K_new, and the plaintext corpus.

Structural layer  +  truth layer:
    for every inventoried record, take the key its epoch says it is under
    (new -> K_new/w_new, old -> K_old/w_old), unwrap, decrypt C_i, and
    compare with the original plaintext.
    "Can this record actually be recovered right now?" — the ground truth.

NOT a proposal. It exists only to label the true fault set so the other
verifiers can be graded (and is itself cross-checked against the fault
manifest, because V3 shares a codebase with them — Methodology §3.12).
"""
from __future__ import annotations

import argparse
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from ..provision import decrypt_record, unwrap
from ..store import EPOCH_NEW, Store
from .common import UNRUNNABLE, Verdict, combine, structural_checks

NAME = "V3"


def truth_layer(run_dir: Path, k_old: bytes | None, k_new: bytes) -> dict:
    flags: dict = {}
    s = Store(run_dir / "store", readonly=True)
    pt = sqlite3.connect(f"file:{run_dir / 'corpus.db'}?mode=ro", uri=True)
    try:
        for rid, body in pt.execute("SELECT id, body FROM plaintext"):
            h = rid.hex()
            try:
                w_old, w_new, _cmt, epoch = s.get_wrap(rid)
                nonce, ct = s.get_payload(rid)
            except KeyError:
                flags.setdefault(h, []).append("TRUTH: record missing")
                continue
            if epoch == EPOCH_NEW:
                kek, w, label = k_new, w_new, "K_new"
            else:
                kek, w, label = k_old, w_old, "K_old"
            if kek is None or w is None:
                flags.setdefault(h, []).append(f"TRUTH: no {label} / wrap to recover with")
                continue
            try:
                dek = unwrap(kek, w)
                if decrypt_record(dek, nonce, ct, rid) != body:
                    flags.setdefault(h, []).append("TRUTH: decrypts to wrong plaintext")
            except InvalidUnwrap:
                flags.setdefault(h, []).append(f"TRUTH: wrap does not unwrap under {label}")
            except InvalidTag:
                flags.setdefault(h, []).append("TRUTH: unrecoverable (wrong DEK or damaged ciphertext)")
    finally:
        pt.close()
        s.close()
    return flags


def verify(run_dir: str | Path, keydir: str | Path | None = None) -> Verdict:
    run_dir = Path(run_dir)
    keydir = Path(keydir) if keydir else run_dir / "keys"
    t0 = time.perf_counter()
    if not (keydir / "kek_new.bin").exists():
        return Verdict(NAME, UNRUNNABLE, notes=["K_new missing"], wall_s=time.perf_counter() - t0)
    k_old_p = keydir / "kek_old.bin"
    k_old = k_old_p.read_bytes() if k_old_p.exists() else None
    s = structural_checks(run_dir)
    kf = truth_layer(run_dir, k_old, (keydir / "kek_new.bin").read_bytes())
    return combine(NAME, s, kf, t0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--keys", default=None)
    a = ap.parse_args()
    v = verify(a.run, a.keys)
    print(v.verdict, len(v.flagged), "flagged", v.notes)
