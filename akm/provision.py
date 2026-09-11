"""
P2 — Bootstrap provisioning ("lock everything up").

For every record i:
    DEK_i   = 32 random bytes                       (the small key)
    nonce_i = 12 random bytes                       (GCM needs one per encryption)
    C_i     = AES-256-GCM(DEK_i, nonce_i, R_i, AD=id_i)   (the locked box)
    w_old_i = AES-KW(K_old, DEK_i)                  (the envelope, 40 bytes)
    cmt_i   = Trunc_tau( SHA-256("AKM-cmt-v1" || DEK_i || id_i) )  (fingerprint)

and store < id, C, nonce, w_old, cmt, epoch=OLD >.

This stage IS "the one trusted rotation" of Research Plan §2.3 — the only
moment a commitment can be installed, because only here does someone hold
the DEK anyway. That is the bootstrapping finding.

Run from the command line:
    python -m akm.provision --seed 1 --N 1000 --size 200 --tau 128 --out runs/demo
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from . import corpus
from .config import RunConfig, derive_bytes
from .store import Store

DEK_BYTES = 32
KEK_BYTES = 32
NONCE_BYTES = 12
CMT_TAG = b"AKM-cmt-v1"   # domain-separation tag (Execution Plan issue 13)


# --------------------------------------------------------------------------
# Small building blocks (reused by the migrator and the verifiers later)
# --------------------------------------------------------------------------
def commitment(dek: bytes, rid: bytes, tau: int) -> bytes:
    """cmt = Trunc_tau(H("AKM-cmt-v1" || DEK || id)). Salt-free (v7).

    id is inside the hash so that swapping DEKs between two records gives
    two mismatches instead of zero (this is what fault F5c tests).
    """
    return hashlib.sha256(CMT_TAG + dek + rid).digest()[: tau // 8]


def encrypt_record(dek: bytes, nonce: bytes, plaintext: bytes, rid: bytes) -> bytes:
    """AES-256-GCM with the record id as associated data (binds C_i to id_i)."""
    return AESGCM(dek).encrypt(nonce, plaintext, rid)


def decrypt_record(dek: bytes, nonce: bytes, ct: bytes, rid: bytes) -> bytes:
    return AESGCM(dek).decrypt(nonce, ct, rid)


def wrap(kek: bytes, dek: bytes) -> bytes:
    """AES Key Wrap (RFC 3394). 32-byte DEK -> 40-byte envelope."""
    return aes_key_wrap(kek, dek)


def unwrap(kek: bytes, w: bytes) -> bytes:
    """Raises cryptography.hazmat.primitives.keywrap.InvalidUnwrap on failure."""
    return aes_key_unwrap(kek, w)


# --------------------------------------------------------------------------
# Key management (models the key manager KM)
# --------------------------------------------------------------------------
def generate_keks(cfg: RunConfig, key_dir: Path) -> tuple[bytes, bytes]:
    """Create K_old and K_new as separate files so they can be mounted separately."""
    key_dir.mkdir(parents=True, exist_ok=True)
    k_old = derive_bytes(cfg.seed, "kek_old", 0, KEK_BYTES)
    k_new = derive_bytes(cfg.seed, "kek_new", 0, KEK_BYTES)
    (key_dir / "kek_old.bin").write_bytes(k_old)
    (key_dir / "kek_new.bin").write_bytes(k_new)
    return k_old, k_new


def dek_for(cfg: RunConfig, i: int) -> bytes:
    return derive_bytes(cfg.seed, "dek", i, DEK_BYTES)


def nonce_for(cfg: RunConfig, i: int) -> bytes:
    return derive_bytes(cfg.seed, "nonce", i, NONCE_BYTES)


# --------------------------------------------------------------------------
# The provisioning run
# --------------------------------------------------------------------------
def provision(cfg: RunConfig, out_dir: str | Path, batch: int = 1000,
              write_corpus: bool = True) -> dict:
    """write_corpus=False skips corpus.db (plaintext copy for V3). Experiment 2
    never runs V3, and at 10^5 x 32 KB the copy would cost another 3.3 GB."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cfg.save(out / "run_config.json")

    t0 = time.perf_counter()
    k_old, _k_new = generate_keks(cfg, out / "keys")
    if write_corpus:
        corpus.write_corpus_db(cfg, out / "corpus.db")
    store = Store.create(out / "store")

    rows = []
    for i, rid, plaintext in corpus.generate(cfg):
        dek = dek_for(cfg, i)
        nonce = nonce_for(cfg, i)
        ct = encrypt_record(dek, nonce, plaintext, rid)
        w_old = wrap(k_old, dek)
        cmt = commitment(dek, rid, cfg.tau)
        rows.append((rid, nonce, ct, w_old, cmt))
        if len(rows) >= batch:
            store.insert_many(rows)
            rows.clear()
    if rows:
        store.insert_many(rows)
    store.commit()   # provisioning is not under test, so one big commit is fine
    elapsed = time.perf_counter() - t0

    sizes = store.tuple_bytes_per_record()
    store.close()
    summary = {
        "run_id": cfg.run_id,
        "N": cfg.N,
        "size": cfg.size,
        "tau": cfg.tau,
        "provision_wall_s": round(elapsed, 3),
        "bytes_per_record": sizes,
    }
    (out / "provision_summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="P2 bootstrap provisioning")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--N", type=int, required=True)
    ap.add_argument("--size", type=int, default=200)
    ap.add_argument("--tau", type=int, default=128)
    ap.add_argument("--out", required=True, help="run directory to create")
    a = ap.parse_args()
    cfg = RunConfig(seed=a.seed, N=a.N, size=a.size, tau=a.tau)
    s = provision(cfg, a.out)
    b = s["bytes_per_record"]
    print(f"run_id            : {s['run_id']}")
    print(f"records           : {s['N']}  in {s['provision_wall_s']} s")
    print(f"tuple (no cmt)    : {b['tuple_without_cmt']:.1f} B/record")
    print(f"commitment field  : {b['cmt']:.1f} B/record  (tau={s['tau']} -> tau/8)")
    print(f"tuple (with cmt)  : {b['tuple_with_cmt']:.1f} B/record")


if __name__ == "__main__":
    main()
