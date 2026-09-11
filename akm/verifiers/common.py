"""
Shared verifier machinery.

THE LADDER IS CUMULATIVE: every rung runs structural_checks() (= V0) and then
adds its own key check. So a verifier's result is

    V0      = structural
    V2minus = structural  ∪  dual-key check
    V2      = structural  ∪  commitment check
    V3      = structural  ∪  full decrypt vs. plaintext

The structural part holds NO keys. It reads: the store (both files),
receipts.bin, bundle.json, inventory files, and public keys in pub/.

Verdicts:
    PASS        complete and consistent
    INCOMPLETE  a valid PARTIAL proof (e.g. after a crash): nothing wrong,
                just not finished. Reports the exact flipped set (F6 scoring).
    FAIL        something is inconsistent; `flagged` names records + reasons
    UNRUNNABLE  this verifier lacks the key material it needs (F7)
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..inventory import load_verified_inventory
from ..merkle import receipt_root, verify_bundle_signature
from ..receipts import STATUS_OK, H, read_log
from ..store import EPOCH_NEW, Store

PASS, FAIL, INCOMPLETE, UNRUNNABLE = "PASS", "FAIL", "INCOMPLETE", "UNRUNNABLE"


@dataclass
class Verdict:
    verifier: str
    verdict: str
    flagged: dict = field(default_factory=dict)     # id hex -> [reasons]
    flipped: list | None = None                     # id hex list, only when INCOMPLETE
    notes: list = field(default_factory=list)       # global problems (bad signature...)
    wall_s: float = 0.0

    def save(self, run_dir: str | Path) -> Path:
        p = Path(run_dir) / f"verdict_{self.verifier}.json"
        p.write_text(json.dumps(asdict(self), indent=2))
        return p


@dataclass
class Structural:
    """What the V0 layer found, handed on to the key layer."""
    flags: dict
    notes: list
    flipped: set
    pending: set
    claimed: str
    tau: int | None
    fatal: bool


def structural_checks(run_dir: str | Path) -> Structural:
    run_dir = Path(run_dir)
    flags = defaultdict(list)
    notes: list = []

    # 1. inventory: signed by the independent anchor, list matches its root
    ids, why = load_verified_inventory(run_dir)
    if ids is None:
        return Structural({}, [why], set(), set(), "?", None, True)

    # 2. bundle: signed by the migrator; root matches the receipt log
    try:
        bundle = json.loads((run_dir / "bundle.json").read_text())
    except FileNotFoundError:
        return Structural({}, ["bundle.json missing"], set(), set(), "?", None, True)
    if not verify_bundle_signature(bundle, run_dir / "pub" / "migrator.pub"):
        return Structural({}, ["bundle signature invalid"], set(), set(), "?", None, True)
    receipts = read_log(run_dir / "receipts.bin")
    if receipt_root(receipts).hex() != bundle["MR"]:
        notes.append("receipt log does not match the signed Merkle root")
    if len(receipts) != bundle["n_receipts"]:
        notes.append("receipt count differs from the signed bundle")
    if bundle["N"] != len(ids):
        notes.append("bundle N differs from the anchored inventory")
    claimed = bundle["claimed"]

    # 3. receipt set vs inventory: duplicates, strangers
    inv = set(ids)
    for rid, c in Counter(r.rid for r in receipts).items():
        if c > 1:
            flags[rid.hex()].append(f"duplicate receipt (x{c})")
        if rid not in inv:
            flags[rid.hex()].append("receipt for an id not in the inventory")

    # 4. per-record consistency between receipts and storage
    by_id = {r.rid: r for r in receipts}
    flipped, pending = set(), set()
    store = Store(run_dir / "store", readonly=True)
    for rid in ids:
        h = rid.hex()
        try:
            w_old, w_new, _cmt, epoch = store.get_wrap(rid)
            _nonce, ct = store.get_payload(rid)
        except KeyError:
            flags[h].append("record missing from store")
            continue
        r = by_id.get(rid)
        if r is None:
            if epoch == EPOCH_NEW:
                flags[h].append("epoch flipped but no receipt (Invariant E violated)")
            elif claimed == "COMPLETE":
                flags[h].append("no receipt: record not migrated")
            continue                                   # not yet migrated; fine if PARTIAL
        if w_new is None:
            flags[h].append("receipt claims migration but no new wrap is stored")
            continue
        if not r.matches(w_new, ct):
            flags[h].append("receipt does not match stored wrap/ciphertext")
        if w_old is not None and H(w_old) != r.h_wold:
            flags[h].append("H(w_old) in receipt does not match stored old wrap")
        if r.status != STATUS_OK or r.epoch != EPOCH_NEW:
            flags[h].append("receipt status/epoch field invalid")
        if epoch == EPOCH_NEW:
            flipped.add(h)
        elif claimed == "COMPLETE":
            flags[h].append("receipt exists but epoch never flipped")
        else:
            pending.add(h)                             # crashed between 6 and 7: allowed
    store.close()
    return Structural(dict(flags), notes, flipped, pending, claimed,
                      bundle["params"]["tau"], False)


def combine(name: str, s: Structural, key_flags: dict | None, t0: float) -> Verdict:
    """Merge the structural layer with a rung's key layer into one verdict."""
    flags = defaultdict(list, {k: list(v) for k, v in s.flags.items()})
    for k, reasons in (key_flags or {}).items():
        flags[k].extend(reasons)
    wall = time.perf_counter() - t0
    if s.fatal or flags or s.notes:
        return Verdict(name, FAIL, dict(flags), None, s.notes, wall)
    if s.claimed != "COMPLETE" or s.pending:
        return Verdict(name, INCOMPLETE, {}, sorted(s.flipped), s.notes, wall)
    return Verdict(name, PASS, {}, None, s.notes, wall)
