"""
Process-level file isolation (Decision 2, PREREG).

install_guard() registers a Python *audit hook*: the interpreter calls it on
every attempt to open a file (builtin open, os.open, pathlib, sqlite3.connect).
Any path inside the run directory that is not on this process's allowlist
raises PermissionError — the file physically cannot be opened by this process.

Why this and not "we just don't call that function": the threat is our own
bugs (a verifier accidentally reading a key file or the answer key). A guard
turns such a bug into a crash instead of a silently wrong result.
Audit hooks cannot be removed once installed.

The Docker Compose setup is the second, stronger layer (files not mounted at all).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

STRUCT = ["store/payload.db", "store/wraps.db", "receipts.bin", "bundle.json",
          "inventory.json", "inventory_ids.bin", "pub/", "run_config.json"]

ROLE_ALLOW = {
    "structural":  STRUCT,
    "v1":          STRUCT + ["merkle_nodes.bin"],
    "v2minus-key": ["store/wraps.db", "keys/v2minus/"],
    "v2-key":      ["store/wraps.db", "keys/v2/"],
    "v3":          STRUCT + ["corpus.db", "keys/v3/"],
}
F7_OVERRIDE = {"v2minus-key": ["store/wraps.db", "keys/f7/"],
               "v2-key":      ["store/wraps.db", "keys/f7/"]}


def allowlist(role: str, keyset: str = "normal") -> list[str]:
    if keyset == "f7" and role in F7_OVERRIDE:
        return F7_OVERRIDE[role]
    return ROLE_ALLOW[role]


def _path_of(event: str, args) -> str | None:
    if event in ("open", "sqlite3.connect") and args:
        p = args[0]
        if isinstance(p, int) or p is None:
            return None
        p = os.fsdecode(p)
        if p.startswith("file:"):
            p = p[5:].split("?", 1)[0]
        return p
    return None


def install_guard(run_dir: str | Path, allow: list[str], extra_files: list[str | Path] = ()) -> None:
    root = Path(run_dir).resolve()
    files = {(root / a).resolve() for a in allow if not a.endswith("/")}
    files |= {Path(f).resolve() for f in extra_files}
    dirs = [str((root / a).resolve()) + os.sep for a in allow if a.endswith("/")]
    root_s = str(root) + os.sep

    def hook(event, args):
        p = _path_of(event, args)
        if p is None or p == ":memory:":
            return
        rp = Path(p).resolve()
        s = str(rp)
        if not s.startswith(root_s):
            return                                   # outside the run dir: Python libs etc.
        if rp in files or any(s.startswith(d) for d in dirs):
            return
        if s.endswith("-journal") and Path(s[: -len("-journal")]) in files:
            return                                   # SQLite's own journal for an allowed db
        raise PermissionError(f"isolation guard: {rp.relative_to(root)} is not allowed here")

    sys.addaudithook(hook)
