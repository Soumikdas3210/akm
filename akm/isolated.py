"""
Isolated verification: every verifier layer runs in its OWN process, guarded.

Child (one per layer):  python -m akm.isolated --role v2-key --run RUN --out FILE ...
    1. installs the audit-hook guard for its role (akm/guard.py) — FIRST
    2. does its layer's work
    3. writes a small JSON result

Parent (the harness): verify_isolated(run_dir) launches the children and merges
their results into the final verdict_<name>.json files.

Split (Execution Plan issue 3):
    structural   = V0's checks, NO keys                     (shared by every rung)
    v1           = challenge-response, NO keys
    v2minus-key  = dual-key compare  — wraps.db + keys/v2minus only (never C_i)
    v2-key       = commitment check  — wraps.db + keys/v2 only      (never C_i)
    v3           = oracle (structural + full decrypt vs plaintext)

The structural layer is computed once and reused by every rung. The ladder is
still cumulative: each rung's verdict = structural result ∪ its own layer,
exactly as if each rung had re-run V0 itself (same deterministic computation).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from .guard import allowlist, install_guard

ALL = ("V0", "V1", "V2minus", "V2", "V3")


# ============================================================ child side ====
def _run_role(role: str, run: Path, keyset: str, k: int, beacon: int, tau: int | None) -> dict:
    t0 = time.perf_counter()
    if role == "structural":
        from .verifiers.common import structural_checks
        s = structural_checks(run)
        out = {"flags": s.flags, "notes": s.notes, "flipped": sorted(s.flipped),
               "pending": sorted(s.pending), "claimed": s.claimed, "tau": s.tau, "fatal": s.fatal}
    elif role == "v1":
        from .verifiers.v1 import challenge_flags
        claimed = json.loads((run / "bundle.json").read_text()).get("claimed") \
            if (run / "bundle.json").exists() else None
        flags = challenge_flags(run, k, beacon)[0] if claimed == "COMPLETE" else {}
        out = {"flags": flags}
    elif role in ("v2minus-key", "v2-key"):
        folder = "f7" if keyset == "f7" else ("v2minus" if role == "v2minus-key" else "v2")
        kd = run / "keys" / folder
        if role == "v2minus-key":
            from .verifiers.v2minus import key_layer
            if not (kd / "kek_old.bin").exists():
                return {"unrunnable": True, "flags": {}, "wall_s": time.perf_counter() - t0}
            flags = key_layer(run / "store", (kd / "kek_old.bin").read_bytes(),
                              (kd / "kek_new.bin").read_bytes())
        else:
            from .verifiers.v2 import key_layer
            flags = key_layer(run / "store", (kd / "kek_new.bin").read_bytes(), tau)
        out = {"unrunnable": False, "flags": flags}
    elif role == "v3":
        from .verifiers.common import structural_checks
        from .verifiers.v3 import truth_layer
        kd = run / "keys" / "v3"
        s = structural_checks(run)
        truth = truth_layer(run, (kd / "kek_old.bin").read_bytes(), (kd / "kek_new.bin").read_bytes())
        out = {"flags": s.flags, "notes": s.notes, "flipped": sorted(s.flipped),
               "pending": sorted(s.pending), "claimed": s.claimed, "tau": s.tau,
               "fatal": s.fatal, "truth": truth}
    else:
        raise ValueError(role)
    out["wall_s"] = time.perf_counter() - t0
    return out


def child_main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--keyset", default="normal")
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--beacon", type=int, default=0)
    ap.add_argument("--tau", type=int, default=None)
    a = ap.parse_args()
    run = Path(a.run).resolve()
    install_guard(run, allowlist(a.role, a.keyset), extra_files=[a.out])   # <- before any work
    result = _run_role(a.role, run, a.keyset, a.k, a.beacon, a.tau)
    Path(a.out).write_text(json.dumps(result))


# =========================================================== parent side ====
def _spawn(role: str, run: Path, keyset: str, k: int, beacon: int, tau: int | None) -> dict:
    out = run / "layers" / f"{role}-{keyset}.json"
    out.parent.mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "akm.isolated", "--role", role, "--run", str(run),
           "--out", str(out), "--keyset", keyset, "--k", str(k), "--beacon", str(beacon)]
    if tau is not None:
        cmd += ["--tau", str(tau)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"layer {role} failed:\n{p.stderr[-2000:]}")
    return json.loads(out.read_text())


def _structural_obj(d: dict):
    from .verifiers.common import Structural
    return Structural(d["flags"], d["notes"], set(d["flipped"]), set(d["pending"]),
                      d["claimed"], d["tau"], d["fatal"])


def verify_isolated(run_dir: str | Path, verifiers=ALL, keyset: str = "normal",
                    k: int = 100, beacon: int = 0, save: bool = True) -> dict[str, dict]:
    """Run the requested verifiers, each layer in its own guarded process.
    Returns {name: verdict-dict}. Also writes verdict_<name>.json unless save=False."""
    from dataclasses import asdict
    from .config import RunConfig
    from .verifiers.common import UNRUNNABLE, Verdict, combine

    run = Path(run_dir).resolve()
    tau_cfg = RunConfig.load(run / "run_config.json").tau
    S_raw = _spawn("structural", run, keyset, k, beacon, None)
    S = _structural_obj(S_raw)
    out: dict[str, dict] = {}

    def finish(name, verdict: Verdict, layer_wall: float):
        verdict.wall_s = S_raw["wall_s"] + layer_wall
        d = asdict(verdict)
        d["mode"] = "cumulative"
        out[name] = d

    if "V0" in verifiers:
        finish("V0", combine("V0", S, None, time.perf_counter()), 0.0)
    if "V1" in verifiers:
        r = _spawn("v1", run, keyset, k, beacon, None)
        finish("V1", combine("V1", S, r["flags"], time.perf_counter()), r["wall_s"])
    if "V2minus" in verifiers:
        r = _spawn("v2minus-key", run, keyset, k, beacon, None)
        if r["unrunnable"]:
            v = Verdict("V2minus", UNRUNNABLE, notes=["K_old retired: audit cannot run (F7)"])
            finish("V2minus", v, r["wall_s"])
        else:
            finish("V2minus", combine("V2minus", S, r["flags"], time.perf_counter()), r["wall_s"])
    if "V2" in verifiers:
        r = _spawn("v2-key", run, keyset, k, beacon, S.tau or tau_cfg)
        finish("V2", combine("V2", S, r["flags"], time.perf_counter()), r["wall_s"])
    if "V3" in verifiers:
        r = _spawn("v3", run, keyset, k, beacon, None)
        v = combine("V3", _structural_obj(r), r["truth"], time.perf_counter())
        v.wall_s = r["wall_s"]
        d = asdict(v); d["mode"] = "cumulative"
        out["V3"] = d

    if save:
        for name, d in out.items():
            (run / f"verdict_{name}{'' if keyset == 'normal' else '_' + keyset}.json").write_text(
                json.dumps(d, indent=2))
    return out


if __name__ == "__main__":
    child_main()
