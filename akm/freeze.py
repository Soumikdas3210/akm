"""
Freeze the results: checksum every result file and record exactly which code
and which pre-registration produced them.

    python -m akm.run freeze --results results            # write results/MANIFEST.json
    python -m akm.run freeze --results results --verify   # anyone can re-check later

Run AFTER `report`, so the manifest also covers REPORT.md and the tables.
Refuses to freeze if the code has uncommitted changes (the manifest would name
a commit that is not what actually ran) unless --allow-dirty, which is recorded.

The per-trial audit folders (thousands of small files) are summarised as one
combined checksum per folder, so the manifest stays readable.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

SKIP_DIRS = {"work", "done"}
AUDIT_DIRS = {"audit"}


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args) -> str | None:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def collect(results: Path) -> tuple[dict, dict]:
    files, trees = {}, {}
    for p in sorted(results.rglob("*")):
        rel = p.relative_to(results)
        if not p.is_file() or rel.parts[0] in SKIP_DIRS or rel.name == "MANIFEST.json":
            continue
        if any(part in SKIP_DIRS for part in rel.parts[:-1]):
            continue
        audit_at = next((i for i, part in enumerate(rel.parts) if part in AUDIT_DIRS), None)
        if audit_at is not None:
            root = "/".join(rel.parts[: audit_at + 1])
            trees.setdefault(root, []).append((rel.as_posix(), _sha(p)))
            continue
        files[rel.as_posix()] = _sha(p)
    tree_sums = {}
    for root, items in trees.items():
        h = hashlib.sha256()
        for name, digest in sorted(items):
            h.update(f"{name}\0{digest}\n".encode())
        tree_sums[root] = {"files": len(items), "sha256": h.hexdigest()}
    return files, tree_sums


def freeze(results: str | Path, allow_dirty: bool = False, smoke: bool = False) -> Path:
    results = Path(results)
    head = _git("rev-parse", "HEAD")
    if head is None and not smoke:
        sys.exit("REFUSING: not inside a git repository, so the code version cannot be recorded.")
    dirty = bool(_git("status", "--porcelain", "--", "akm", "tests", "requirements.txt", "PREREG.md"))
    if dirty and not allow_dirty:
        sys.exit("REFUSING: uncommitted changes to code or PREREG.md. Commit first, "
                 "or pass --allow-dirty (it will be recorded in the manifest).")
    prereg = _git("log", "--reverse", "--format=%H %ad", "--date=iso", "--", "PREREG.md")
    envs = {}
    for e in results.glob("*/environment.json"):
        d = json.loads(e.read_text())
        envs[e.parent.name] = {"code_commit": d.get("code_commit"), "prereg_commit": d.get("prereg_commit"),
                               "smoke": d.get("smoke")}
    warnings = []
    for name, d in envs.items():
        if d["code_commit"] and head and d["code_commit"] != head:
            warnings.append(f"{name} was produced by commit {d['code_commit'][:10]}, freezing at "
                            f"{head[:10]}: state in the paper whether the code changed in between")
        if d["smoke"]:
            warnings.append(f"{name} is a SMOKE run")
    if not (results / "REPORT.md").exists():
        warnings.append("REPORT.md not found: run `report` before `freeze` so the manifest covers it")
    files, trees = collect(results)
    manifest = {"frozen_at": time.strftime("%Y-%m-%d %H:%M:%S %z"), "code_commit": head,
                "code_dirty": dirty, "prereg_history": prereg.splitlines() if prereg else [],
                "experiments": envs, "warnings": warnings, "files": files, "audit_trees": trees}
    out = results / "MANIFEST.json"
    out.write_text(json.dumps(manifest, indent=2))
    for w in warnings:
        print("WARNING:", w)
    print(f"froze {len(files)} files + {len(trees)} audit folders -> {out}")
    return out


def verify(results: str | Path) -> bool:
    results = Path(results)
    m = json.loads((results / "MANIFEST.json").read_text())
    files, trees = collect(results)
    bad = [f for f, h in m["files"].items() if files.get(f) != h]
    missing = [f for f in m["files"] if f not in files]
    extra = [f for f in files if f not in m["files"]]
    bad_trees = [t for t, d in m["audit_trees"].items() if trees.get(t) != d]
    for label, lst in (("CHANGED", [b for b in bad if b not in missing]), ("MISSING", missing),
                       ("NOT IN MANIFEST", extra), ("AUDIT FOLDER CHANGED", bad_trees)):
        for f in lst:
            print(f"  {label}: {f}")
    ok = not (bad or extra or bad_trees)
    print("VERIFIED: every result file matches the manifest" if ok else "VERIFICATION FAILED")
    return ok
