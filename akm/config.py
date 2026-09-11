"""
P0 — Configuration & seeding.

Two jobs:
  1. RunConfig: every knob of one experiment run, saved as run_config.json,
     so any run can be reproduced exactly from that file.
  2. derive_bytes(): a *seeded* deterministic random-byte generator (DRBG).

Why a seeded DRBG and not os.urandom()?  (Execution Plan, issue 10)
  The methodology wants runs reproducible from (seed, N, size). Real systems
  draw DEKs from the OS CSPRNG, but then two runs can never be identical.
  Detection results do not depend on the *values* of the keys, so for the
  experiment we derive every "random" byte from SHAKE-256(seed, label, index).
  This is labelled EXPERIMENT ONLY — never use it for real keys.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

VALID_SIZES = (200, 2048, 32768)      # record payload sizes in bytes
VALID_TAUS = (64, 96, 128, 256)       # commitment tag lengths in bits
DRBG_DOMAIN = b"AKM-drbg-v1"          # domain-separation tag for the DRBG


# --------------------------------------------------------------------------
# Deterministic "random" bytes  (EXPERIMENT ONLY)
# --------------------------------------------------------------------------
def derive_bytes(seed: int, label: str, index: int, n: int) -> bytes:
    """Return n pseudo-random bytes that depend only on (seed, label, index).

    - seed  : the run seed (the one number that makes a run reproducible)
    - label : what the bytes are for ("dek", "nonce", "id", ...). Different
              labels give independent streams, so the DEK of record 5 has
              nothing to do with the nonce of record 5.
    - index : usually the record number i.

    Stateless on purpose: record i always gets the same bytes, no matter in
    which order records are generated. That keeps things reproducible even
    if we later parallelise.
    """
    if not (0 <= seed < 2**63):
        raise ValueError("seed must be in [0, 2^63)")
    msg = (
        DRBG_DOMAIN
        + b"|" + seed.to_bytes(8, "big")
        + b"|" + label.encode("ascii")
        + b"|" + index.to_bytes(8, "big")
    )
    return hashlib.shake_256(msg).digest(n)


def derive_int(seed: int, label: str, index: int, upper: int) -> int:
    """Deterministic integer in [0, upper). Used later for picking fault targets."""
    # 16 bytes = 128 bits, so modulo bias is negligible for any realistic upper.
    return int.from_bytes(derive_bytes(seed, label, index, 16), "big") % upper


# --------------------------------------------------------------------------
# Run configuration
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class RunConfig:
    seed: int
    N: int                      # number of records in the corpus
    size: int                   # plaintext payload size per record (bytes)
    tau: int = 128              # commitment tag length (bits)
    k: int = 100                # number of V1 challenges (used from Week 6)
    fsync_policy: str = "per_record"   # "per_record" or "group:<B>" (issue 8)
    run_id: str = ""            # filled in automatically if left empty

    def __post_init__(self) -> None:
        if self.size not in VALID_SIZES:
            raise ValueError(f"size must be one of {VALID_SIZES}, got {self.size}")
        if self.tau not in VALID_TAUS:
            raise ValueError(f"tau must be one of {VALID_TAUS}, got {self.tau}")
        if self.N < 1:
            raise ValueError("N must be >= 1")
        if not (self.fsync_policy == "per_record" or self.fsync_policy.startswith("group:")):
            raise ValueError("fsync_policy must be 'per_record' or 'group:<B>'")
        if not self.run_id:
            # frozen dataclass -> must use object.__setattr__ to fill it in
            object.__setattr__(
                self, "run_id",
                f"s{self.seed}-N{self.N}-b{self.size}-t{self.tau}",
            )

    @property
    def tag_bytes(self) -> int:
        return self.tau // 8

    @property
    def group_size(self) -> int:
        """B for group-commit; 1 means fsync every record."""
        if self.fsync_policy == "per_record":
            return 1
        return int(self.fsync_policy.split(":", 1)[1])

    # ---- save / load ------------------------------------------------------
    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "RunConfig":
        return cls(**json.loads(Path(path).read_text()))
