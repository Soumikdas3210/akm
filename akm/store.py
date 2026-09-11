"""
Storage layer — the "warehouse".

The logical record tuple from the methodology is
    < id_i, C_i, nonce_i, w_old_i, cmt_i, e_i >
(+ w_new_i once the migration writes it).

DESIGN DECISION (made in Week 1 to save pain in Week 4):
The tuple is physically split across TWO SQLite files:

    payload.db  : id, nonce, ct            <- the encrypted data (C_i)
    wraps.db    : id, w_old, w_new, cmt, epoch   <- the key envelopes

Why? Execution Plan issue 3: the V2 "key process" must NEVER be able to read
C_i. If everything lived in one file, the key process would have the
ciphertext on disk even if our code never reads it. With two files, Docker
simply does not mount payload.db into the key process — isolation is
*enforced*, not promised.

SQLite settings:
  synchronous=FULL  -> every COMMIT is fsync'd to disk (durability, needed
                       by Algorithm 1's crash-safe ordering in Week 2).
  journal_mode=DELETE -> classic rollback journal. Chosen over WAL because
                       WAL databases are awkward to open from read-only
                       Docker mounts, which is exactly what verifiers get.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

EPOCH_OLD = 0
EPOCH_NEW = 1
EPOCH_FIELD_BYTES = 1   # e_i is counted as 1 byte in the logical tuple


def _connect(path: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        con = sqlite3.connect(path)
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
    return con


class Store:
    """Handle to one run's store directory (store/payload.db + store/wraps.db)."""

    def __init__(self, store_dir: str | Path, readonly: bool = False,
                 need_payload: bool = True, need_wraps: bool = True):
        self.dir = Path(store_dir)
        self.payload = _connect(self.dir / "payload.db", readonly) if need_payload else None
        self.wraps = _connect(self.dir / "wraps.db", readonly) if need_wraps else None

    # ---- creation -----------------------------------------------------------
    @classmethod
    def create(cls, store_dir: str | Path) -> "Store":
        d = Path(store_dir)
        d.mkdir(parents=True, exist_ok=True)
        for name in ("payload.db", "wraps.db"):
            f = d / name
            if f.exists():
                f.unlink()
        s = cls(d)
        s.payload.execute(
            "CREATE TABLE payload (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL)"
        )
        s.wraps.execute(
            "CREATE TABLE wraps (id BLOB PRIMARY KEY, w_old BLOB, w_new BLOB, "
            "cmt BLOB NOT NULL, epoch INTEGER NOT NULL)"
        )
        s.payload.commit()
        s.wraps.commit()
        return s

    # ---- bulk insert (provisioning) ----------------------------------------
    def insert_many(self, rows: list[tuple[bytes, bytes, bytes, bytes, bytes]]) -> None:
        """rows = [(id, nonce, ct, w_old, cmt), ...]; epoch starts at OLD."""
        self.payload.executemany(
            "INSERT INTO payload (id, nonce, ct) VALUES (?,?,?)",
            [(r[0], r[1], r[2]) for r in rows],
        )
        self.wraps.executemany(
            "INSERT INTO wraps (id, w_old, w_new, cmt, epoch) VALUES (?,?,NULL,?,?)",
            [(r[0], r[3], r[4], EPOCH_OLD) for r in rows],
        )

    def commit(self) -> None:
        if self.payload:
            self.payload.commit()
        if self.wraps:
            self.wraps.commit()

    # ---- reads ---------------------------------------------------------------
    def count(self) -> int:
        return self.wraps.execute("SELECT COUNT(*) FROM wraps").fetchone()[0]

    def get_payload(self, rid: bytes) -> tuple[bytes, bytes]:
        """Return (nonce, ct) for one record."""
        row = self.payload.execute("SELECT nonce, ct FROM payload WHERE id=?", (rid,)).fetchone()
        if row is None:
            raise KeyError(rid.hex())
        return row[0], row[1]

    def get_wrap(self, rid: bytes) -> tuple[bytes | None, bytes | None, bytes, int]:
        """Return (w_old, w_new, cmt, epoch) for one record."""
        row = self.wraps.execute(
            "SELECT w_old, w_new, cmt, epoch FROM wraps WHERE id=?", (rid,)
        ).fetchone()
        if row is None:
            raise KeyError(rid.hex())
        return row[0], row[1], row[2], row[3]

    def iter_ids(self):
        # list() so the cursor is finished before callers issue writes
        return [rid for (rid,) in self.wraps.execute("SELECT id FROM wraps ORDER BY id")]

    def iter_new_wraps(self):
        """(id, w_old, w_new, cmt) for every record that HAS a new wrap.
        Reads wraps.db only — this is all a key process ever needs."""
        return self.wraps.execute(
            "SELECT id, w_old, w_new, cmt FROM wraps WHERE w_new IS NOT NULL ORDER BY id"
        ).fetchall()

    # ---- writes used by the migrator (Algorithm 1) ---------------------------
    def set_w_new(self, rid: bytes, w_new: bytes) -> None:
        """Step 5: write the new wrap into the shadow slot (not yet committed)."""
        self.wraps.execute("UPDATE wraps SET w_new=? WHERE id=?", (w_new, rid))

    def set_epoch(self, rid: bytes, epoch: int) -> None:
        """Step 7: flip the epoch pointer (not yet committed)."""
        self.wraps.execute("UPDATE wraps SET epoch=? WHERE id=?", (epoch, rid))

    def set_ct(self, rid: bytes, ct: bytes) -> None:
        """Used ONLY by the fault harness for post-hoc F3 (bit-flip)."""
        self.payload.execute("UPDATE payload SET ct=? WHERE id=?", (ct, rid))

    # ---- storage accounting (feeds storage.csv) ------------------------------
    def tuple_bytes_per_record(self) -> dict[str, float]:
        """Average LOGICAL bytes per record, by field.

        We count field lengths, not the .db file size: SQLite adds page and
        index overhead that is an artefact of our tool, not of the scheme.
        (id is stored in both files for joining, but counted once.)
        """
        n = self.count()
        p = self.payload.execute(
            "SELECT SUM(length(id)), SUM(length(nonce)), SUM(length(ct)) FROM payload"
        ).fetchone()
        w = self.wraps.execute(
            "SELECT SUM(length(w_old)), SUM(COALESCE(length(w_new),0)), SUM(length(cmt)) FROM wraps"
        ).fetchone()
        id_b, nonce_b, ct_b = (x / n for x in p)
        wold_b, wnew_b, cmt_b = ((x or 0) / n for x in w)
        base = id_b + ct_b + nonce_b + wold_b + EPOCH_FIELD_BYTES
        return {
            "id": id_b, "ct": ct_b, "nonce": nonce_b, "w_old": wold_b,
            "w_new": wnew_b, "epoch": EPOCH_FIELD_BYTES, "cmt": cmt_b,
            "tuple_without_cmt": base,
            "tuple_with_cmt": base + cmt_b,
        }

    def close(self) -> None:
        for c in (self.payload, self.wraps):
            if c:
                c.close()
