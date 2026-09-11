"""
P5 — The fault harness ("the saboteur").

Every fault is reproducible from (seed, fault, eps). The harness:
  1. picks target records deterministically from the seed,
  2. returns a migrate.Hooks object (migration-time faults) and/or applies a
     post-hoc mutation to a finished artifact (F3, F4r, F4m),
  3. writes private/fault_manifest.json — THE ANSWER KEY. It lives under
     private/, which no verifier process is allowed to open (akm/guard.py).

Fault table (mirrors PREREG.md):
  F0   honest control                      -
  F1a  skip, no receipt                    migration
  F1b  skip, fake success receipt          migration
  F2   duplicate receipt                   migration
  F3   ciphertext bit-flip                 post-hoc on an F0 copy
  F4r  one receipt byte edited             post-hoc on an F0 copy
  F4m  signed Merkle root edited           post-hoc on an F0 copy
  F5   wrong DEK, well-formed wrap         migration, between steps 2 and 3
  F5b  garbage wrap (40 random bytes)      migration, after the self-check
  F5c  DEK swap between two records        migration, between steps 2 and 3
  F6   crash at the 6->7 boundary          migration (always per-record fsync)
  F7   audit after K_old retired           verification (F5 artifact, keys/f7)
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import derive_bytes, derive_int
from .migrate import Hooks
from .receipts import RECEIPT_SIZE, read_log
from .store import EPOCH_NEW, Store

ALL_FAULTS = ("F0", "F1a", "F1b", "F2", "F3", "F4r", "F4m", "F5", "F5b", "F5c", "F6", "F7")
MIGRATION_FAULTS = {"F0", "F1a", "F1b", "F2", "F5", "F5b", "F5c", "F6"}
POSTHOC_FAULTS = {"F3", "F4r", "F4m"}
EPS_ALLOWED = {"F1b", "F3", "F5"}          # faults that may corrupt a fraction eps of records

INJECTION = {
    "F0": "-", "F1a": "migrate:entry", "F1b": "migrate:entry", "F2": "migrate:step6",
    "F3": "posthoc:ciphertext", "F4r": "posthoc:receipt-log", "F4m": "posthoc:bundle-root",
    "F5": "migrate:between-2-3", "F5b": "migrate:after-step4", "F5c": "migrate:between-2-3",
    "F6": "migrate:boundary-6-7", "F7": "verify:K_old-retired",
}


def n_targets(fault: str, eps: float, N: int) -> int:
    if fault in ("F0", "F4m", "F6", "F7"):
        return 0
    if fault == "F5c":
        return 2
    if eps:
        if fault not in EPS_ALLOWED:
            raise ValueError(f"{fault} does not take eps")
        return max(1, round(eps * N))
    return 1


def choose_targets(ids: list[bytes], seed: int, fault: str, count: int) -> list[bytes]:
    """`count` distinct records, chosen deterministically from the seed."""
    if count > len(ids):
        raise ValueError("more targets than records")
    picked, seen, j = [], set(), 0
    while len(picked) < count:
        i = derive_int(seed, f"fault-{fault}", j, len(ids))
        j += 1
        if i not in seen:
            seen.add(i)
            picked.append(ids[i])
    return picked


def crash_position(seed: int, N: int) -> int:
    """F6: where in the migration order the worker is killed (never at the very ends)."""
    return 1 + derive_int(seed, "fault-F6-pos", 0, N - 2)


def migration_hooks(fault: str, targets: list[bytes], seed: int, N: int) -> Hooks:
    if fault == "F0":
        return Hooks()
    if fault == "F1a":
        return Hooks(skip_no_receipt=set(targets))
    if fault == "F1b":
        return Hooks(skip_with_receipt=set(targets))
    if fault == "F2":
        return Hooks(duplicate_receipt=set(targets))
    if fault == "F5":
        return Hooks(wrong_dek={t: derive_bytes(seed, "evil", j, 32) for j, t in enumerate(targets)})
    if fault == "F5b":
        return Hooks(garbage_wrap={t: derive_bytes(seed, "junk", j, 40) for j, t in enumerate(targets)})
    if fault == "F5c":
        a, b = targets
        return Hooks(dek_from={a: b, b: a})
    if fault == "F6":
        return Hooks(crash=(crash_position(seed, N), "6-7"))
    raise ValueError(f"{fault} is not a migration-time fault")


def apply_posthoc(run_dir: str | Path, fault: str, targets: list[bytes], seed: int) -> dict:
    """Mutate a finished (honest) artifact. Returns details for the manifest."""
    run_dir = Path(run_dir)
    if fault == "F3":
        s = Store(run_dir / "store")
        bits = []
        for j, t in enumerate(targets):
            _nonce, ct = s.get_payload(t)
            bit = derive_int(seed, "f3-bit", j, len(ct) * 8)
            b = bytearray(ct)
            b[bit // 8] ^= 1 << (bit % 8)
            s.set_ct(t, bytes(b))
            bits.append(bit)
        s.commit()
        s.close()
        return {"bits": bits}
    if fault == "F4r":
        log = run_dir / "receipts.bin"
        data = bytearray(log.read_bytes())
        position = [r.rid for r in read_log(log)].index(targets[0])
        off = 1 + derive_int(seed, "f4r-byte", 0, RECEIPT_SIZE - 1)   # never the version byte
        data[position * RECEIPT_SIZE + off] ^= 0xFF
        log.write_bytes(bytes(data))
        return {"receipt_index": position, "byte_offset": off}
    if fault == "F4m":
        p = run_dir / "bundle.json"
        b = json.loads(p.read_text())
        mr = bytearray.fromhex(b["MR"])
        mr[derive_int(seed, "f4m-byte", 0, 32)] ^= 0xFF
        b["MR"] = mr.hex()
        p.write_text(json.dumps(b, indent=2))
        return {}
    raise ValueError(f"{fault} is not a post-hoc fault")


def flipped_set(run_dir: str | Path) -> list[str]:
    """Ground truth for F6: which records' epoch pointers actually flipped."""
    s = Store(Path(run_dir) / "store", readonly=True, need_payload=False)
    out = sorted(rid.hex() for rid in s.iter_ids() if s.get_wrap(rid)[3] == EPOCH_NEW)
    s.close()
    return out


def write_manifest(run_dir: str | Path, fault: str, eps: float, seed: int,
                   targets: list[bytes], **extra) -> Path:
    d = Path(run_dir) / "private"
    d.mkdir(exist_ok=True)
    m = {"fault": fault, "eps": eps, "seed": seed, "injection": INJECTION[fault],
         "targets": sorted(t.hex() for t in targets), **extra}
    p = d / "fault_manifest.json"
    p.write_text(json.dumps(m, indent=2))
    return p


def read_manifest(run_dir: str | Path) -> dict:
    return json.loads((Path(run_dir) / "private" / "fault_manifest.json").read_text())
