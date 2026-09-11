"""
P1 — Corpus synthesis.

Generates fake JSON-like records of an EXACT byte size (200 B, 2 KB, 32 KB).
No real or sensitive data is used anywhere in the project.

The plaintext is written to its own SQLite file, corpus.db, which is kept
separate from the encrypted store on purpose: later, only the V3 oracle is
allowed to see plaintext, and the easiest way to enforce that is "nobody
else gets this file mounted".
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterator

from .config import RunConfig, derive_bytes, derive_int

_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ID_BYTES = 16   # 128-bit record identifiers


def record_id(seed: int, i: int) -> bytes:
    """Stable 128-bit identifier id_i for record i."""
    return derive_bytes(seed, "id", i, ID_BYTES)


def _ascii_filler(seed: int, i: int, n: int) -> str:
    raw = derive_bytes(seed, "pad", i, n)
    return bytes(_ALPHABET[b % len(_ALPHABET)] for b in raw).decode("ascii")


def make_record(seed: int, i: int, size: int) -> bytes:
    """Build record i as compact JSON whose UTF-8 length is exactly `size`."""
    body = {
        "rec": i,
        "user": f"user_{derive_int(seed, 'user', i, 10**6):06d}",
        "email": f"u{derive_int(seed, 'mail', i, 10**6):06d}@example.org",
        "balance_cents": derive_int(seed, "bal", i, 10**9),
        "created": f"2026-0{1 + derive_int(seed, 'mon', i, 9)}-1{derive_int(seed, 'day', i, 9)}",
        "pad": "",
    }
    base = json.dumps(body, separators=(",", ":"), sort_keys=True)
    pad_len = size - len(base)
    if pad_len < 0:
        raise ValueError(f"record skeleton ({len(base)} B) larger than size {size}")
    body["pad"] = _ascii_filler(seed, i, pad_len)
    out = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")
    assert len(out) == size, (len(out), size)
    return out


def generate(cfg: RunConfig) -> Iterator[tuple[int, bytes, bytes]]:
    """Yield (i, id_i, plaintext_i) for i = 0 .. N-1."""
    for i in range(cfg.N):
        yield i, record_id(cfg.seed, i), make_record(cfg.seed, i, cfg.size)


def write_corpus_db(cfg: RunConfig, path: str | Path, batch: int = 1000) -> None:
    """Write all plaintext records to corpus.db (ground truth for V3 only)."""
    path = Path(path)
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE plaintext (idx INTEGER PRIMARY KEY, id BLOB UNIQUE NOT NULL, body BLOB NOT NULL)")
    rows = []
    for i, rid, body in generate(cfg):
        rows.append((i, rid, body))
        if len(rows) >= batch:
            con.executemany("INSERT INTO plaintext VALUES (?,?,?)", rows)
            rows.clear()
    if rows:
        con.executemany("INSERT INTO plaintext VALUES (?,?,?)", rows)
    con.commit()
    con.close()
