"""
P6 — Merkle tree and the signed proof bundle.

Merkle tree, RFC 6962 style (the Certificate Transparency construction):
    leaf node     = H(0x00 || data)
    internal node = H(0x01 || left || right)
    odd node out at a level is PROMOTED unchanged, never duplicated.

Why not the simpler "duplicate the last node" trick (as Bitcoin does)?
Because then the lists [a, b, c] and [a, b, c, c] have the SAME root —
a duplicated receipt (fault F2!) would be invisible to the root check.
The 0x00/0x01 prefixes stop a leaf ever being confused with an internal
node (another classic Merkle bug).

Bundle: the migrator M publishes
    { MR, n_receipts, N, claimed: COMPLETE|PARTIAL, params, t1 }  +  sig_M
where MR is the root over all receipts in the log, sorted.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .config import RunConfig, derive_bytes
from .receipts import Receipt, read_log

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
BUNDLE_TAG = b"AKM-bundle-v1"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root over a list of byte strings (order matters)."""
    if not leaves:
        return _h(b"")
    level = [_h(LEAF_PREFIX + x) for x in leaves]
    while len(level) > 1:
        nxt = [_h(NODE_PREFIX + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])          # promote, don't duplicate
        level = nxt
    return level[0]


def receipt_root(receipts: list[Receipt]) -> bytes:
    """MR = root over the full 83-byte encodings, sorted (=> sorted by id).
    Using the whole encoding means editing ANY byte of any receipt moves MR."""
    return merkle_root(sorted(r.encode() for r in receipts))


# --------------------------------------------------------------------------
# Migrator signing key (sk_M) — experiment-only, derived from the seed
# --------------------------------------------------------------------------
def migrator_key(cfg: RunConfig, run_dir: Path) -> Ed25519PrivateKey:
    sk = Ed25519PrivateKey.from_private_bytes(derive_bytes(cfg.seed, "sk_M", 0, 32))
    (run_dir / "keys").mkdir(exist_ok=True)
    (run_dir / "pub").mkdir(exist_ok=True)
    (run_dir / "keys" / "migrator_sk.bin").write_bytes(derive_bytes(cfg.seed, "sk_M", 0, 32))
    (run_dir / "pub" / "migrator.pub").write_bytes(sk.public_key().public_bytes_raw())
    return sk


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def build_bundle(run_dir: str | Path, claimed: str = "COMPLETE") -> dict:
    """Stage P6. Reads receipts.bin as it is on disk and signs its root."""
    run_dir = Path(run_dir)
    cfg = RunConfig.load(run_dir / "run_config.json")
    receipts = read_log(run_dir / "receipts.bin")
    body = {
        "run_id": cfg.run_id,
        "epoch_id": "new",
        "N": cfg.N,
        "n_receipts": len(receipts),
        "claimed": claimed,
        "MR": receipt_root(receipts).hex(),
        "params": {"tau": cfg.tau, "aead": "AES-256-GCM", "wrap": "AES-KW-RFC3394",
                   "receipt_format": "v1-83B"},
        "t1": int(time.time()),
    }
    # store the internal nodes: the migrator needs them to answer V1 challenges,
    # and their size is the merkle_bytes_per_rec column of storage.csv
    write_nodes(run_dir / "merkle_nodes.bin", build_levels(sorted(r.encode() for r in receipts)))
    sk = migrator_key(cfg, run_dir)
    bundle = dict(body, sig=sk.sign(BUNDLE_TAG + _canonical(body)).hex())
    (run_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    return bundle


def verify_bundle_signature(bundle: dict, pub_path: str | Path) -> bool:
    body = {k: v for k, v in bundle.items() if k != "sig"}
    pk = Ed25519PublicKey.from_public_bytes(Path(pub_path).read_bytes())
    try:
        pk.verify(bytes.fromhex(bundle["sig"]), BUNDLE_TAG + _canonical(body))
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------
# Stored tree + inclusion proofs (Day 2: needed by V1, measured in storage.csv)
# --------------------------------------------------------------------------
NODES_MAGIC = b"AKMT"   # merkle_nodes.bin = MAGIC | n_leaves(8) | internal levels, bottom-up


def build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """All levels, level 0 = leaf hashes, last level = [root]. Same shape as merkle_root()."""
    level = [_h(LEAF_PREFIX + x) for x in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = [_h(NODE_PREFIX + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        levels.append(nxt)
        level = nxt
    return levels


def write_nodes(path: str | Path, levels: list[list[bytes]]) -> int:
    """Store INTERNAL levels only (level >= 1). Leaf hashes are recomputable from
    the receipt log, so storing them would double-count. Returns bytes written."""
    n = len(levels[0])
    body = b"".join(b"".join(lv) for lv in levels[1:])
    blob = NODES_MAGIC + n.to_bytes(8, "big") + body
    Path(path).write_bytes(blob)
    return len(blob)


def read_nodes(path: str | Path, leaf_level: list[bytes]) -> list[list[bytes]]:
    blob = Path(path).read_bytes()
    if blob[:4] != NODES_MAGIC:
        raise ValueError("not a merkle_nodes.bin file")
    n = int.from_bytes(blob[4:12], "big")
    if n != len(leaf_level):
        raise ValueError("stored tree does not match the receipt log")
    levels, off, size = [leaf_level], 12, n
    while size > 1:
        size = (size + 1) // 2
        levels.append([blob[off + 32 * i: off + 32 * (i + 1)] for i in range(size)])
        off += 32 * size
    return levels


def inclusion_proof(levels: list[list[bytes]], index: int) -> list[tuple[bytes | None, bool]]:
    """Sibling path from leaf `index` to the root.
    Each step is (sibling_hash, sibling_is_left) or (None, False) when the node was PROMOTED."""
    proof = []
    for lv in levels[:-1]:
        if index == len(lv) - 1 and len(lv) % 2 == 1:
            proof.append((None, False))                  # odd one out: promoted unchanged
        else:
            sib = index ^ 1
            proof.append((lv[sib], sib < index))
        index //= 2
    return proof


def verify_inclusion(leaf_data: bytes, proof: list[tuple[bytes | None, bool]], root: bytes) -> bool:
    h = _h(LEAF_PREFIX + leaf_data)
    for sib, sib_is_left in proof:
        if sib is None:
            continue
        h = _h(NODE_PREFIX + sib + h) if sib_is_left else _h(NODE_PREFIX + h + sib)
    return h == root
