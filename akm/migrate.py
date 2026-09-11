"""
P4 — The migration: Algorithm 1, v7 ordering.

For each record (in id order):
  1. Read  <id, w_old, C, e>
  2. DEK   <- Unwrap(K_old, w_old)            abort record on failure
       -- F5 / F5c are injected HERE, between steps 2 and 3 (Plan issue 4) --
  3. w_new <- Wrap(K_new, DEK)
  4. Self-check: Unwrap(K_new, w_new) == DEK  (a control, not assurance)
       -- F5b (garbage wrap) is injected HERE, after the self-check --
  5. Write w_new to the shadow slot;           COMMIT + fsync
  6. Append receipt to the durable log;        fsync          <- v7: BEFORE the flip
  7. Flip epoch old -> new;                    COMMIT + fsync

Invariant E: receipts ⊇ flipped records, at every instant.

Batching (fsync_policy "group:B", Execution Plan issue 8):
  steps 1-4 run for B records, then step 5 for all B + one fsync, then step 6
  for all B + one fsync, then step 7 for all B + one fsync. The ORDER of the
  three durability points is unchanged, so Invariant E still holds per batch.
  With B = 1 ("per_record") this is exactly Algorithm 1.

Why fault hooks live INSIDE the migrator: faults F1, F2, F5, F6 model a buggy
migrator. The harness (Day 2) only fills in a Hooks object; the migrator obeys
it. An honest run passes Hooks() = no faults.
"""
from __future__ import annotations

import argparse
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from .config import RunConfig
from .provision import unwrap, wrap
from .receipts import Receipt, ReceiptLog, read_log, repair_torn_tail
from .store import EPOCH_NEW, EPOCH_OLD, Store

BOUNDARIES = ("5-6", "6-7")


class SimulatedCrash(Exception):
    """Raised to 'kill' the migrator at a phase boundary (fault F6)."""


@dataclass
class Hooks:
    skip_no_receipt: set = field(default_factory=set)    # F1a: never touched, no receipt
    skip_with_receipt: set = field(default_factory=set)  # F1b: untouched, receipt says done
    duplicate_receipt: set = field(default_factory=set)  # F2 : receipt written twice
    wrong_dek: dict = field(default_factory=dict)        # F5 : id -> DEK' (well-formed wrong key)
    dek_from: dict = field(default_factory=dict)         # F5c: id -> partner id (use partner's DEK)
    garbage_wrap: dict = field(default_factory=dict)     # F5b: id -> 40 random bytes
    crash: tuple | None = None                           # F6 : (record position, "5-6" | "6-7")
    hard_crash: bool = False                             # F6 : True = os._exit (real kill)


def _load_keks(key_dir: Path) -> tuple[bytes, bytes]:
    return (key_dir / "kek_old.bin").read_bytes(), (key_dir / "kek_new.bin").read_bytes()


def migrate(run_dir: str | Path, hooks: Hooks | None = None, fsync_policy: str | None = None,
            emit_receipts: bool = True, resume: bool = False) -> dict:
    run_dir = Path(run_dir)
    hooks = hooks or Hooks()
    cfg = RunConfig.load(run_dir / "run_config.json")
    if fsync_policy:
        cfg = RunConfig(**{**cfg.__dict__, "fsync_policy": fsync_policy})
    B = cfg.group_size
    k_old, k_new = _load_keks(run_dir / "keys")
    log_path = run_dir / "receipts.bin"

    t_wall, t_cpu = time.perf_counter(), time.process_time()
    store = Store(run_dir / "store")
    ids = store.iter_ids()
    position = {rid: i for i, rid in enumerate(ids)}

    # ---- resume: reconcile what a previous (crashed) run left behind ----------
    existing = {}
    if resume:
        repair_torn_tail(log_path)
        existing = {r.rid: r for r in read_log(log_path)}
    elif log_path.exists():
        log_path.unlink()                       # fresh run: start a fresh log
    log = ReceiptLog(log_path) if emit_receipts else None

    todo, flip_only = [], []
    for rid in ids:
        w_old, w_new, _cmt, epoch = store.get_wrap(rid)
        if epoch == EPOCH_NEW:
            continue                            # finished before the crash
        if rid in existing and w_new is not None:
            _nonce, ct = store.get_payload(rid)
            if existing[rid].matches(w_new, ct):
                flip_only.append(rid)           # crashed between 6 and 7: replay step 7
                continue
        todo.append(rid)                        # (re)do from step 1; AES-KW is deterministic
    for rid in flip_only:
        store.set_epoch(rid, EPOCH_NEW)
    store.commit()

    stats = {"migrated": 0, "aborted": [], "resumed_flips": len(flip_only), "crashed": None}

    def maybe_crash(batch_ids, boundary):
        if hooks.crash and hooks.crash[1] == boundary:
            target = hooks.crash[0]
            if any(position[r] == target for r in batch_ids):
                stats["crashed"] = boundary
                if hooks.hard_crash:
                    # A REAL kill: the process vanishes instantly, no cleanup,
                    # no Python buffers flushed. Faithful to "worker is killed".
                    os._exit(137)
                raise SimulatedCrash(f"killed at {boundary} on record position {target}")

    try:
        for start in range(0, len(todo), B):
            batch = todo[start:start + B]
            work = []   # (rid, w_new to store or None, [receipts], flip?)

            for rid in batch:
                if rid in hooks.skip_no_receipt:                      # F1a
                    continue
                # step 1
                w_old, _w_new, _cmt, _e = store.get_wrap(rid)
                _nonce, ct = store.get_payload(rid)
                # step 2
                try:
                    dek = unwrap(k_old, w_old)
                except InvalidUnwrap:
                    stats["aborted"].append(rid.hex())
                    continue
                # ---- F5 / F5c injection point (between steps 2 and 3) ----
                if rid in hooks.wrong_dek:
                    dek = hooks.wrong_dek[rid]
                elif rid in hooks.dek_from:
                    dek = unwrap(k_old, store.get_wrap(hooks.dek_from[rid])[0])
                # step 3
                w_new = wrap(k_new, dek)
                # step 4: self-check (passes under F5 because it uses the same wrong DEK)
                if unwrap(k_new, w_new) != dek:
                    stats["aborted"].append(rid.hex())
                    continue
                # ---- F5b injection point (after the self-check) ----
                if rid in hooks.garbage_wrap:
                    w_new = hooks.garbage_wrap[rid]

                rcpt = Receipt.build(rid, w_old, w_new, ct, EPOCH_NEW)
                if rid in hooks.skip_with_receipt:                    # F1b
                    work.append((rid, None, [rcpt], False))
                else:
                    copies = 2 if rid in hooks.duplicate_receipt else 1   # F2
                    work.append((rid, w_new, [rcpt] * copies, True))

            # step 5: shadow slot, durable
            for rid, w_new, _r, _f in work:
                if w_new is not None:
                    store.set_w_new(rid, w_new)
            store.commit()                                  # fsync (synchronous=FULL)
            maybe_crash(batch, "5-6")

            # step 6: receipts, durable — BEFORE the flip
            if log:
                for _rid, _w, receipts, _f in work:
                    for r in receipts:
                        log.append(r)
                log.sync()
            maybe_crash(batch, "6-7")

            # step 7: flip, durable
            for rid, _w, _r, flip in work:
                if flip:
                    store.set_epoch(rid, EPOCH_NEW)
                    stats["migrated"] += 1
            store.commit()
    finally:
        if log:
            log.close()
        store.close()

    stats["wall_s"] = time.perf_counter() - t_wall
    stats["cpu_s"] = time.process_time() - t_cpu
    stats["fsync_policy"] = cfg.fsync_policy
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description="P4 migration (Algorithm 1)")
    ap.add_argument("--run", required=True)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--fsync", default=None, help="per_record or group:<B>")
    ap.add_argument("--crash-at", default=None,
                    help='F6: kill the process for real, e.g. "500:6-7"')
    a = ap.parse_args()
    hooks = Hooks()
    if a.crash_at:
        pos, boundary = a.crash_at.split(":")
        if boundary not in BOUNDARIES:
            ap.error(f"boundary must be one of {BOUNDARIES}")
        hooks = Hooks(crash=(int(pos), boundary), hard_crash=True)
    s = migrate(a.run, hooks=hooks, fsync_policy=a.fsync, resume=a.resume)
    print(f"migrated {s['migrated']} records in {s['wall_s']:.2f} s "
          f"(cpu {s['cpu_s']:.2f} s, {s['fsync_policy']}); aborted {len(s['aborted'])}")


if __name__ == "__main__":
    main()
