"""Day 1 tests: migrator, receipt log, crash/resume, and the verifier ladder.

Run with:  python -m pytest -v tests/test_day1.py
"""
import hashlib
import json
import shutil
import subprocess
import sys

import pytest

from akm.config import RunConfig, derive_bytes
from akm.inventory import build_inventory
from akm.merkle import build_bundle
from akm.migrate import Hooks, SimulatedCrash, migrate
from akm.pipeline import build, verify_all
from akm.provision import provision
from akm.receipts import RECEIPT_SIZE, read_log, repair_torn_tail
from akm.store import EPOCH_NEW, Store

N = 300


# ---------------------------------------------------------------- helpers ----
def fresh(run_dir, seed=1, fsync="per_record"):
    """P0-P3 only (provisioned + inventoried, NOT migrated)."""
    cfg = RunConfig(seed=seed, N=N, size=200, tau=128, fsync_policy=fsync)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    provision(cfg, run_dir)
    build_inventory(run_dir)
    return cfg


def ids_in_order(run_dir):
    s = Store(run_dir / "store", readonly=True, need_payload=False)
    ids = s.iter_ids()
    s.close()
    return ids


def flipped_ids(run_dir):
    s = Store(run_dir / "store", readonly=True, need_payload=False)
    out = {rid for rid in s.iter_ids() if s.get_wrap(rid)[3] == EPOCH_NEW}
    s.close()
    return out


def receipt_ids(run_dir):
    return [r.rid for r in read_log(run_dir / "receipts.bin")]


def verdicts(run_dir, keydir=None):
    return {n: v for n, v in verify_all(run_dir, keydir).items()}


def assert_invariant_E(run_dir):
    """Receipts are a SUPERSET of flipped records — the v7 fix."""
    assert flipped_ids(run_dir) <= set(receipt_ids(run_dir))


# ------------------------------------------------------------ honest runs ----
@pytest.mark.parametrize("seed", range(1, 11))
def test_honest_runs_pass_everywhere_10_seeds(tmp_path, seed):
    """Quality gate 1: every verifier PASSes honest runs on >= 10 seeds."""
    run = tmp_path / "r"
    cfg = RunConfig(seed=seed, N=N, size=200, tau=128)
    st = build(cfg, run)
    assert st["migrated"] == N and st["aborted"] == []
    assert len(receipt_ids(run)) == N
    assert_invariant_E(run)
    for name, v in verdicts(run).items():
        assert v.verdict == "PASS", (name, v.flagged, v.notes)


def test_group_commit_gives_identical_result(tmp_path):
    """Issue 8: group commit must change speed only, never the outcome."""
    def digest(run):
        s = Store(run / "store", readonly=True)
        rows = list(s.wraps.execute("SELECT id, w_new, epoch FROM wraps ORDER BY id"))
        s.close()
        return hashlib.sha256(repr(rows).encode() + (run / "receipts.bin").read_bytes()).hexdigest()
    a, b = tmp_path / "a", tmp_path / "b"
    fresh(a); migrate(a)
    fresh(b); migrate(b, fsync_policy="group:64")
    assert digest(a) == digest(b)


# ------------------------------------------- F5 family: the headline result --
def test_F5_wrong_dek_V0_blind_key_rungs_catch(tmp_path):
    """The paper in one test: V0 says PASS on a destroyed record; V2⁻/V2/V3 catch it."""
    run = tmp_path / "r"
    cfg = RunConfig(seed=3, N=N, size=200, tau=128)
    target = None

    def hooks_for(run_dir):
        nonlocal target
        target = ids_in_order(run_dir)[123]
        return Hooks(wrong_dek={target: derive_bytes(99, "evil", 0, 32)})

    shutil.rmtree(run, ignore_errors=True)
    provision(cfg, run); build_inventory(run)
    st = migrate(run, hooks=hooks_for(run))
    build_bundle(run)
    assert st["migrated"] == N, "self-check must PASS under F5 (issue 4 injection point)"
    v = verdicts(run)
    assert v["V0"].verdict == "PASS"                     # predicted blind spot (P1)
    for name in ("V2minus", "V2", "V3"):
        assert v[name].verdict == "FAIL"
        assert set(v[name].flagged) == {target.hex()}, name   # exactly that record


def test_F5b_garbage_wrap_is_the_easy_case(tmp_path):
    run = tmp_path / "r"
    fresh(run, seed=4)
    t = ids_in_order(run)[7]
    migrate(run, hooks=Hooks(garbage_wrap={t: derive_bytes(4, "junk", 0, 40)}))
    build_bundle(run)
    v = verdicts(run)
    assert v["V0"].verdict == "PASS"                     # V0 still blind
    assert v["V2minus"].flagged[t.hex()] == ["new wrap does not unwrap under K_new"]
    assert v["V2"].flagged[t.hex()] == ["new wrap does not unwrap under K_new"]


def test_F5c_dek_swap_gives_two_mismatches(tmp_path):
    """Why id is inside the commitment: a swap yields TWO flags, not zero."""
    run = tmp_path / "r"
    fresh(run, seed=5)
    ids = ids_in_order(run)
    a, b = ids[10], ids[20]
    migrate(run, hooks=Hooks(dek_from={a: b, b: a}))
    build_bundle(run)
    v = verdicts(run)
    assert v["V0"].verdict == "PASS"
    assert set(v["V2"].flagged) == {a.hex(), b.hex()}
    assert set(v["V2minus"].flagged) == {a.hex(), b.hex()}


# -------------------------------------------------- F7: K_old is retired ----
def test_F7_only_row_separating_V2minus_from_V2(tmp_path):
    run = tmp_path / "r"
    fresh(run, seed=6)
    t = ids_in_order(run)[50]
    migrate(run, hooks=Hooks(wrong_dek={t: derive_bytes(6, "evil", 0, 32)}))
    build_bundle(run)
    retired = tmp_path / "keys_after_retirement"
    retired.mkdir()
    shutil.copy(run / "keys" / "kek_new.bin", retired)       # K_old is gone
    assert v2minus_verdict(run, retired) == "UNRUNNABLE"
    from akm.verifiers import v2
    vv = v2.verify(run, retired)
    assert vv.verdict == "FAIL" and set(vv.flagged) == {t.hex()}   # V2 still works


def v2minus_verdict(run, keydir):
    from akm.verifiers import v2minus
    return v2minus.verify(run, keydir).verdict


# ------------------------------------------------ F6: crash and resume -------
@pytest.mark.parametrize("boundary", ["5-6", "6-7"])
@pytest.mark.parametrize("fsync", ["per_record", "group:32"])
def test_crash_leaves_describable_state_and_resumes(tmp_path, boundary, fsync):
    run = tmp_path / "r"
    fresh(run, seed=7, fsync=fsync)
    pos = 150
    with pytest.raises(SimulatedCrash):
        migrate(run, hooks=Hooks(crash=(pos, boundary)))

    # --- state right after the crash ---
    assert_invariant_E(run)
    n_flipped = len(flipped_ids(run))
    assert 0 < n_flipped < N
    build_bundle(run, claimed="PARTIAL")        # the partial paperwork
    v = verdicts(run)
    for name in ("V0", "V2minus", "V2", "V3"):
        if name == "V3":
            continue                             # V3 judges recoverability, see below
        assert v[name].verdict == "INCOMPLETE", (name, v[name].flagged, v[name].notes)
        assert set(v[name].flipped) == {r.hex() for r in flipped_ids(run)}  # exact set (F6 rule)
    assert v["V3"].verdict in ("PASS", "INCOMPLETE")   # every record still recoverable

    # --- resume and finish ---
    st = migrate(run, resume=True)
    if boundary == "6-7":
        assert st["resumed_flips"] > 0          # receipt existed, only step 7 replayed
    assert_invariant_E(run)
    rids = receipt_ids(run)
    assert len(rids) == len(set(rids)) == N, "resume must not duplicate receipts"
    build_bundle(run, claimed="COMPLETE")
    for name, vv in verdicts(run).items():
        assert vv.verdict == "PASS", (name, vv.flagged, vv.notes)


def test_real_process_kill_at_6_7(tmp_path):
    """Same as above, but the migrator process is killed for real (os._exit)."""
    run = tmp_path / "r"
    fresh(run, seed=8)
    p = subprocess.run([sys.executable, "-m", "akm.migrate", "--run", str(run),
                        "--crash-at", "200:6-7"], capture_output=True)
    assert p.returncode == 137, p.stderr.decode()
    assert_invariant_E(run)
    assert len(receipt_ids(run)) == len(flipped_ids(run)) + 1    # one receipt ahead of the flips
    p = subprocess.run([sys.executable, "-m", "akm.migrate", "--run", str(run), "--resume"],
                       capture_output=True)
    assert p.returncode == 0, p.stderr.decode()
    build_bundle(run)
    assert all(v.verdict == "PASS" for v in verdicts(run).values())


def test_torn_receipt_tail_is_ignored_and_repaired(tmp_path):
    run = tmp_path / "r"
    fresh(run, seed=9)
    migrate(run)
    log = run / "receipts.bin"
    with open(log, "ab") as f:
        f.write(b"\x01" * 40)                   # half a receipt: crash mid-write
    assert len(read_log(log)) == N
    assert repair_torn_tail(log) == 40
    assert log.stat().st_size == N * RECEIPT_SIZE


def test_resume_on_finished_run_changes_nothing(tmp_path):
    run = tmp_path / "r"
    fresh(run, seed=10)
    migrate(run)
    before = (run / "receipts.bin").read_bytes()
    st = migrate(run, resume=True)
    assert st["migrated"] == 0 and st["resumed_flips"] == 0
    assert (run / "receipts.bin").read_bytes() == before


# --------------------------------- structural faults: V0 must catch these ----
def _v0(run):
    from akm.verifiers import v0
    return v0.verify(run)


def test_V0_catches_F1a_skip_no_receipt(tmp_path):
    run = tmp_path / "r"; fresh(run, seed=11); t = ids_in_order(run)[5]
    migrate(run, hooks=Hooks(skip_no_receipt={t})); build_bundle(run)
    assert _v0(run).verdict == "FAIL" and t.hex() in _v0(run).flagged


def test_V0_catches_F1b_skip_with_fake_receipt(tmp_path):
    run = tmp_path / "r"; fresh(run, seed=12); t = ids_in_order(run)[5]
    migrate(run, hooks=Hooks(skip_with_receipt={t})); build_bundle(run)
    v = _v0(run)
    assert v.verdict == "FAIL" and t.hex() in v.flagged


def test_V0_catches_F2_duplicate(tmp_path):
    run = tmp_path / "r"; fresh(run, seed=13); t = ids_in_order(run)[5]
    migrate(run, hooks=Hooks(duplicate_receipt={t})); build_bundle(run)
    v = _v0(run)
    assert v.verdict == "FAIL" and any("duplicate" in r for r in v.flagged[t.hex()])


def test_V0_catches_F3_ciphertext_bitflip(tmp_path):
    run = tmp_path / "r"; fresh(run, seed=14); migrate(run); build_bundle(run)
    t = ids_in_order(run)[5]
    s = Store(run / "store")
    _n, ct = s.get_payload(t)
    s.set_ct(t, bytes([ct[0] ^ 0x01]) + ct[1:]); s.commit(); s.close()
    v = _v0(run)
    assert v.verdict == "FAIL" and set(v.flagged) == {t.hex()}


def test_V0_catches_F4_edited_receipt_and_edited_root(tmp_path):
    run = tmp_path / "r"; fresh(run, seed=15); migrate(run); build_bundle(run)
    # (a) edit one byte inside a receipt, after the root was signed
    log = run / "receipts.bin"
    data = bytearray(log.read_bytes()); data[60] ^= 0xFF; log.write_bytes(bytes(data))
    assert _v0(run).verdict == "FAIL"
    # (b) edit the signed root itself
    b = json.loads((run / "bundle.json").read_text())
    b["MR"] = "00" * 32
    (run / "bundle.json").write_text(json.dumps(b))
    v = _v0(run)
    assert v.verdict == "FAIL" and "bundle signature invalid" in v.notes
