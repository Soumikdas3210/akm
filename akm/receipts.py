"""
Receipt format — FROZEN in Week 1 (Execution Plan issue 7).

A receipt is the migrator's "paperwork" for one record. The leaf hash is

    rho_i = SHA-256( "AKM-rcpt-v1" || id || H(w_old) || H(w_new) || H(C) || e || status )

What we STORE per record in the append-only receipt log (83 bytes, fixed):

    offset  size  field
    0       1     version   (0x01)
    1       16    id_i
    17      1     epoch     (target epoch, 0x01 = NEW)
    18      1     status    (0x01 = MIGRATED_OK)
    19      32    H(w_old_i)
    51      32    rho_i     (the leaf)
    ------  ----
            83 bytes

Why these fields and not others:
  * H(w_old) MUST be stored: after K_old is retired, w_old may be deleted
    from storage, and then nobody could recompute it. (This is why the old
    "32 B/record" figure was a lower bound.)
  * H(w_new) and H(C) are NOT stored: a verifier recomputes them from the
    store. If someone edits w_new or C afterwards, the recomputed leaf will
    no longer match rho_i, which is exactly how V0 catches F3 / F4.
  * rho_i IS stored: it lets V0 say WHICH record is bad (the flagged set),
    and it doubles as a torn-write check after a crash.
  * Fixed length: a crash mid-append leaves a file whose length is not a
    multiple of 83, so the torn tail is trivially detectable.

Merkle internal nodes are NOT part of this format; whether the tree is
stored (≈ +32 B/record) is decided in Week 3 and measured separately.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

RECEIPT_VERSION = 1
LEAF_TAG = b"AKM-rcpt-v1"
STATUS_OK = 0x01
_FMT = ">B16sBB32s32s"                 # big-endian, no padding
RECEIPT_SIZE = struct.calcsize(_FMT)   # = 83
assert RECEIPT_SIZE == 83


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(rid: bytes, h_wold: bytes, h_wnew: bytes, h_ct: bytes,
              epoch: int, status: int) -> bytes:
    return H(LEAF_TAG + rid + h_wold + h_wnew + h_ct + bytes([epoch, status]))


@dataclass(frozen=True)
class Receipt:
    rid: bytes
    epoch: int
    status: int
    h_wold: bytes
    leaf: bytes

    def encode(self) -> bytes:
        return struct.pack(_FMT, RECEIPT_VERSION, self.rid, self.epoch,
                           self.status, self.h_wold, self.leaf)

    @classmethod
    def decode(cls, blob: bytes) -> "Receipt":
        if len(blob) != RECEIPT_SIZE:
            raise ValueError(f"receipt must be {RECEIPT_SIZE} bytes, got {len(blob)}")
        ver, rid, epoch, status, h_wold, leaf = struct.unpack(_FMT, blob)
        if ver != RECEIPT_VERSION:
            raise ValueError(f"unknown receipt version {ver}")
        return cls(rid, epoch, status, h_wold, leaf)

    @classmethod
    def build(cls, rid: bytes, w_old: bytes, w_new: bytes, ct: bytes,
              epoch: int, status: int = STATUS_OK) -> "Receipt":
        """Compute a receipt from the actual bytes (used by the migrator)."""
        h_wold = H(w_old)
        leaf = leaf_hash(rid, h_wold, H(w_new), H(ct), epoch, status)
        return cls(rid, epoch, status, h_wold, leaf)

    def matches(self, w_new: bytes, ct: bytes) -> bool:
        """Recompute the leaf from current storage and compare (used by V0)."""
        return leaf_hash(self.rid, self.h_wold, H(w_new), H(ct),
                         self.epoch, self.status) == self.leaf


# --------------------------------------------------------------------------
# The append-only receipt log  (Algorithm 1, step 6)
# --------------------------------------------------------------------------
import os
from pathlib import Path


class ReceiptLog:
    """Append-only binary file of 83-byte receipts.

    append() only hands bytes to Python/the OS. sync() is the fsync that makes
    them survive a power cut. Algorithm 1 calls sync() at step 6, BEFORE the
    epoch flip at step 7 — that ordering is the whole v7 crash fix.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        is_new = not self.path.exists()
        self._f = open(self.path, "ab")
        if is_new:
            # A brand-new file's directory entry is only durable once the
            # DIRECTORY is fsync'd too. Without this, a crash could lose the
            # whole log file even though its contents were fsync'd.
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    def append(self, r: Receipt) -> None:
        self._f.write(r.encode())

    def sync(self) -> None:
        self._f.flush()                 # Python buffer -> OS
        os.fsync(self._f.fileno())      # OS cache -> physical disk

    def close(self) -> None:
        self._f.close()


def read_log(path: str | Path) -> list[Receipt]:
    """Read every COMPLETE receipt. A torn last record (crash mid-write)
    leaves a length that isn't a multiple of 83; that tail is ignored."""
    p = Path(path)
    if not p.exists():
        return []
    data = p.read_bytes()
    usable = len(data) - len(data) % RECEIPT_SIZE
    return [Receipt.decode(data[i:i + RECEIPT_SIZE]) for i in range(0, usable, RECEIPT_SIZE)]


def repair_torn_tail(path: str | Path) -> int:
    """Truncate a torn tail so appends line up again. Returns bytes removed."""
    p = Path(path)
    if not p.exists():
        return 0
    size = p.stat().st_size
    extra = size % RECEIPT_SIZE
    if extra:
        with open(p, "r+b") as f:
            f.truncate(size - extra)
            f.flush()
            os.fsync(f.fileno())
    return extra
