"""
Isolation probe (quality gate 1).

    python -m akm.isolation_probe --role v2-key --run RUN          # guard on
    python -m akm.isolation_probe --role v2-key --run RUN --no-guard   # control

Tries to open every file in the run directory that the role must NOT see
(key files outside its folder, payload.db for key layers, corpus.db, and
private/fault_manifest.json). Exit code = number of files it managed to open.
    guard on  -> must be 0
    --no-guard-> must be > 0   (proves the probe itself can find leaks)
The same module runs inside Docker for the formal test.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from .guard import allowlist, install_guard


def forbidden_files(run: Path, role: str, keyset: str = "normal") -> list[Path]:
    allow = allowlist(role, keyset)
    files = [p for p in run.rglob("*") if p.is_file() and "layers" not in p.parts
             and not p.name.startswith("verdict_")]
    out = []
    for p in files:
        rel = p.relative_to(run).as_posix()
        ok = rel in allow or any(a.endswith("/") and rel.startswith(a) for a in allow)
        if not ok:
            out.append(p)
    return out


# Every file a complete run directory contains. In Docker, anything not mounted
# simply does not exist — so the probe must try this FIXED list, not rglob().
CANON = ["store/payload.db", "store/wraps.db", "receipts.bin", "bundle.json", "inventory.json",
         "inventory_ids.bin", "pub/anchor.pub", "pub/migrator.pub", "run_config.json",
         "merkle_nodes.bin", "corpus.db", "keys/kek_old.bin", "keys/kek_new.bin",
         "keys/anchor_sk.bin", "keys/migrator_sk.bin", "keys/v2minus/kek_old.bin",
         "keys/v2minus/kek_new.bin", "keys/v2/kek_new.bin", "keys/v3/kek_old.bin",
         "keys/v3/kek_new.bin", "keys/f7/kek_new.bin", "private/fault_manifest.json"]


def _allowed(rel: str, allow: list[str]) -> bool:
    return rel in allow or any(a.endswith("/") and rel.startswith(a) for a in allow)


def try_open(p: Path) -> bool:
    try:
        if p.suffix == ".db":
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            con.execute("SELECT name FROM sqlite_master").fetchall()
            con.close()
        else:
            with open(p, "rb") as f:
                f.read(1)
        return True
    except (PermissionError, FileNotFoundError, sqlite3.DatabaseError):
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--keyset", default="normal")
    ap.add_argument("--no-guard", action="store_true")
    ap.add_argument("--docker", action="store_true",
                    help="container mode: try the fixed CANON list; unmounted files must be absent")
    a = ap.parse_args()
    run = Path(a.run).resolve()
    if a.docker:
        allow = allowlist(a.role, a.keyset)
        missing = [r for r in CANON if _allowed(r, allow) and not (run / r).exists()
                   and not r.startswith(("keys/", "merkle"))]
        forbidden = [r for r in CANON if not _allowed(r, allow)]
        leaks = [r for r in forbidden if try_open(run / r)]
        print(f"[docker] role={a.role} forbidden={len(forbidden)} leaks={len(leaks)} {leaks[:5]}"
              + (f"  WARNING allowed-but-missing={missing}" if missing else ""))
        sys.exit(len(leaks))
    targets = forbidden_files(run, a.role, a.keyset)   # listed BEFORE the guard goes up
    must_have = [run / "private" / "fault_manifest.json"]
    if a.role in ("v2-key", "v2minus-key"):
        must_have.append(run / "store" / "payload.db")
    missing = [m for m in must_have if m not in targets]
    if missing:
        print("probe setup error: expected forbidden files not present:", missing)
        sys.exit(99)
    if not a.no_guard:
        install_guard(run, allowlist(a.role, a.keyset))
    leaks = [p.relative_to(run).as_posix() for p in targets if try_open(p)]
    print(f"role={a.role} checked={len(targets)} leaks={len(leaks)} {leaks[:5]}")
    sys.exit(len(leaks))


if __name__ == "__main__":
    main()
