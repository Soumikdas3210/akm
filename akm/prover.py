"""
The migrator's side of V1's challenge-response protocol.

V1 holds no keys. It asks the migrator M: "prove record r was migrated".
M answers from whatever is ACTUALLY in storage (Proposition 1, step 2: the
honest answering procedure applied to a corrupted state) with:
    - the receipt for r (83 bytes) and its Merkle inclusion proof,
    - the stored w_new and C_r (so V1 can recompute the receipt's leaf).
M uses its stored tree (merkle_nodes.bin) so each answer costs O(log N).

`reads` counts store lookups so a test can prove V1-S reads only k records.
"""
from __future__ import annotations

from pathlib import Path

from .merkle import _h, LEAF_PREFIX, inclusion_proof, read_nodes
from .receipts import RECEIPT_SIZE
from .store import Store


class Prover:
    def __init__(self, run_dir: str | Path):
        run_dir = Path(run_dir)
        raw = (run_dir / "receipts.bin").read_bytes()
        usable = len(raw) - len(raw) % RECEIPT_SIZE
        self.encodings = sorted(raw[i:i + RECEIPT_SIZE] for i in range(0, usable, RECEIPT_SIZE))
        leaf_level = [_h(LEAF_PREFIX + e) for e in self.encodings]
        self.levels = read_nodes(run_dir / "merkle_nodes.bin", leaf_level) if self.encodings else [[]]
        self.index = {}
        for i, e in enumerate(self.encodings):
            self.index.setdefault(e[1:17], i)            # rid = bytes 1..16 of the encoding
        self.store = Store(run_dir / "store", readonly=True)
        self.reads = 0

    def answer(self, rid: bytes) -> dict:
        self.reads += 1
        try:
            _w_old, w_new, _cmt, _epoch = self.store.get_wrap(rid)
            _nonce, ct = self.store.get_payload(rid)
        except KeyError:
            return {"receipt": None, "proof": None, "w_new": None, "ct": None}
        i = self.index.get(rid)
        if i is None:
            return {"receipt": None, "proof": None, "w_new": w_new, "ct": ct}
        return {"receipt": self.encodings[i], "proof": inclusion_proof(self.levels, i),
                "w_new": w_new, "ct": ct}

    def close(self) -> None:
        self.store.close()
