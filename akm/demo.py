"""
Live demonstration for the defense (~15 seconds):

    python -m akm.run demo              # 1,000 records
    python -m akm.run demo --N 5000

Tells the paper's story on real data, step by step:
  1. build a warehouse of encrypted records
  2. migrate to a new master key, but seal ONE record with the WRONG key (F5)
     -> the migrator's own self-check still passes
  3. the paperwork inspector V0 audits everything        -> PASS (blind)
  4. the spot-checker V1 challenges THAT exact record      -> accepts it (blind)
  5. the key-holding inspectors V2-minus and V2            -> FAIL, naming that record
  6. the oracle V3 confirms the record is unrecoverable
  7. retire the old key (F7): V2-minus can no longer run, V2 still catches it

Nothing is simulated: every step calls the same code the experiments use.
"""
from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path


def _say(step: str, text: str, pause: float) -> None:
    print(f"\n[{step}] {text}", flush=True)
    time.sleep(pause)


def run_demo(N: int = 1000, pause: float = 0.6, keep: bool = False) -> dict:
    from .config import RunConfig, derive_bytes
    from .faults import choose_targets, migration_hooks
    from .inventory import build_inventory
    from .keys_stage import stage_keys
    from .merkle import build_bundle
    from .migrate import migrate
    from .prover import Prover
    from .provision import provision
    from .store import Store
    from .verifiers import v0, v2, v2minus, v3
    from .verifiers.v1 import _global_checks, check_answer, verify_sampling

    tmp = Path(tempfile.mkdtemp(prefix="akm-demo-"))
    run = tmp / "run"
    out = {}
    try:
        cfg = RunConfig(seed=2026, N=N, size=200, tau=128, fsync_policy="group:500")
        _say("1", f"Building a warehouse of {N:,} encrypted records "
                  "(each with its own key, sealed under master key K_old)...", 0)
        s = provision(cfg, run)
        build_inventory(run)
        print(f"    done: {s['bytes_per_record']['tuple_without_cmt']:.0f} bytes stored per record "
              f"+ a {cfg.tau // 8}-byte fingerprint of each record's key")

        st = Store(run / "store", readonly=True, need_payload=False)
        ids = st.iter_ids()
        st.close()
        target = choose_targets(ids, cfg.seed, "F5", 1)[0]
        short = target.hex()[:12]
        _say("2", f"Migrating every record to the new master key K_new ...\n"
                  f"    SABOTAGE: record {short}... gets sealed with the WRONG key (fault F5).", pause)
        m = migrate(run, hooks=migration_hooks("F5", [target], cfg.seed, N))
        build_bundle(run)
        stage_keys(run)
        print(f"    migrated {m['migrated']:,} records, self-check failures: {len(m['aborted'])}")
        print("    -> the migrator's own self-check PASSED: the bad record looks perfectly normal.")
        out["self_check_aborts"] = len(m["aborted"])

        vv0 = v0.verify(run)
        _say("3", "V0, the paperwork inspector (no keys): checks signatures, the Merkle root, "
                  "every receipt against storage...", pause)
        print(f"    V0 verdict: {vv0.verdict}   records flagged: {len(vv0.flagged)}")
        out["V0"] = vv0.verdict

        _say("4", f"V1, the spot-checker (no keys): let it challenge record {short}... DIRECTLY.", pause)
        _ids, MR, _notes, _fatal = _global_checks(run)
        p = Prover(run)
        reasons = check_answer(target, p.answer(target), MR)
        p.close()
        print(f"    challenge on the damaged record: {'REJECTED: ' + reasons[0] if reasons else 'ACCEPTED'}")
        print(f"    V1-S with 100 random challenges: {verify_sampling(run, 100, beacon=7).verdict}")
        print("    -> it looked straight at the destroyed record and had nothing to catch it with.")
        out["V1_direct"] = "REJECTED" if reasons else "ACCEPTED"

        _say("5", "Now the inspectors that hold keys (they see only key envelopes, never the data)...", pause)
        vm, vv2 = v2minus.verify(run, run / "keys" / "v2minus"), v2.verify(run, run / "keys" / "v2")
        for name, v in (("V2-minus (K_old + K_new)", vm), ("V2 (K_new + fingerprint)", vv2)):
            hit = [f"{h[:12]}..." for h in v.flagged]
            print(f"    {name:26s}: {v.verdict}   flagged: {hit}")
        out["V2minus"], out["V2"] = vm.verdict, vv2.verdict
        out["V2_exact"] = set(vv2.flagged) == {target.hex()}

        _say("6", "V3, the oracle (holds everything): can that record still be decrypted?", pause)
        vv3 = v3.verify(run, run / "keys" / "v3")
        reason = next(iter(vv3.flagged.values()), ["-"])[-1]
        print(f"    V3 verdict: {vv3.verdict}   reason: {reason}")
        out["V3"] = vv3.verdict

        _say("7", "Finally, the old master key K_old is retired (fault F7)...", pause)
        f7m, f7 = v2minus.verify(run, run / "keys" / "f7"), v2.verify(run, run / "keys" / "f7")
        print(f"    V2-minus: {f7m.verdict}   (it needs K_old, which no longer exists)")
        print(f"    V2:       {f7.verdict}   (the fingerprint was installed at the start; K_new is enough)")
        out["F7_V2minus"], out["F7_V2"] = f7m.verdict, f7.verdict

        print("\n" + "=" * 72)
        print("  Paperwork and spot checks cannot see a wrong key: V0 PASS, V1 accepts it.")
        print("  Key-holding checks catch it and name the exact record.")
        print("  Only the fingerprint check (V2) still works after the old key is gone.")
        print("=" * 72)
        return out
    finally:
        if keep:
            print(f"\n(artifacts kept in {run})")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
