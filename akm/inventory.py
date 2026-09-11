"""
P3 — Inventory anchoring.

BEFORE migration, an independent party A (not the migrator!) publishes the
list of every record ID and signs its Merkle root:

    IR   = MerkleRoot( sort({id_i}) )
    sig_A = Sign(sk_A, "AKM-inv-v1" || IR || N || t0)

Why this matters (Companion §7): if the migrator produced both the list of
records AND the receipts, "every record has a receipt" would mean nothing —
it could just leave a record off both. The anchor fixes the list first.

Files written:
    inventory_ids.bin   16 bytes per id, sorted   (public)
    inventory.json      {IR, N, t0, sig}          (public)
    pub/anchor.pub      A's public key            (public)
    keys/anchor_sk.bin  A's signing key           (only A holds this)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .config import RunConfig, derive_bytes
from .corpus import ID_BYTES
from .merkle import merkle_root
from .store import Store

INV_TAG = b"AKM-inv-v1"


def _signed_bytes(ir: bytes, n: int, t0: int) -> bytes:
    return INV_TAG + ir + n.to_bytes(8, "big") + t0.to_bytes(8, "big")


def build_inventory(run_dir: str | Path) -> dict:
    run_dir = Path(run_dir)
    cfg = RunConfig.load(run_dir / "run_config.json")
    store = Store(run_dir / "store", readonly=True, need_payload=False)
    ids = sorted(store.iter_ids())
    store.close()

    ir = merkle_root(ids)
    t0 = int(time.time())
    sk_bytes = derive_bytes(cfg.seed, "sk_A", 0, 32)
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)

    (run_dir / "keys").mkdir(exist_ok=True)
    (run_dir / "pub").mkdir(exist_ok=True)
    (run_dir / "keys" / "anchor_sk.bin").write_bytes(sk_bytes)
    (run_dir / "pub" / "anchor.pub").write_bytes(sk.public_key().public_bytes_raw())
    (run_dir / "inventory_ids.bin").write_bytes(b"".join(ids))

    inv = {"IR": ir.hex(), "N": len(ids), "t0": t0,
           "sig": sk.sign(_signed_bytes(ir, len(ids), t0)).hex()}
    (run_dir / "inventory.json").write_text(json.dumps(inv, indent=2))
    return inv


def load_verified_inventory(run_dir: str | Path) -> tuple[list[bytes] | None, str]:
    """Return (sorted id list, "") if the inventory verifies, else (None, reason)."""
    run_dir = Path(run_dir)
    try:
        inv = json.loads((run_dir / "inventory.json").read_text())
        raw = (run_dir / "inventory_ids.bin").read_bytes()
        pk = Ed25519PublicKey.from_public_bytes((run_dir / "pub" / "anchor.pub").read_bytes())
    except FileNotFoundError as e:
        return None, f"inventory file missing: {e.filename}"
    ids = [raw[i:i + ID_BYTES] for i in range(0, len(raw), ID_BYTES)]
    ir = bytes.fromhex(inv["IR"])
    try:
        pk.verify(bytes.fromhex(inv["sig"]), _signed_bytes(ir, inv["N"], inv["t0"]))
    except (InvalidSignature, ValueError):
        return None, "inventory signature invalid"
    if len(ids) != inv["N"] or merkle_root(ids) != ir:
        return None, "inventory id list does not match signed root"
    return ids, ""
