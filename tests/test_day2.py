"""Day 2 tests. Run with:  python -m pytest -v tests/test_day2.py"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from akm.config import RunConfig, derive_bytes
from akm.faults import (apply_posthoc, choose_targets, migration_hooks, n_targets,
                        read_manifest, write_manifest)
from akm.inventory import build_inventory
from akm.merkle import (build_levels, inclusion_proof, merkle_root, read_nodes,
                        verify_inclusion, write_nodes)
from akm.migrate import migrate
from akm.merkle import build_bundle
from akm.pipeline import build
from akm.provision import provision
from akm.prover import Prover
from akm.score import GroundTruthConflict, cross_check, detected, wilson
from akm.store import Store
from akm.verifiers.v1 import first_failures, verify_cumulative, verify_sampling
from akm.verifiers.v0 import verify as v0_verify


# ------------------------------------------------------------- helpers -------
def fresh(run, seed=1, N=300, fsync="group:100"):
    cfg = RunConfig(seed=seed, N=N, size=200, tau=128, fsync_policy=fsync)
    shutil.rmtree(run, ignore_errors=True)
    provision(cfg, run)
    build_inventory(run)
    return cfg


def ids_of(run):
    s = Store(run / "store", readonly=True, need_payload=False)
    ids = s.iter_ids()
    s.close()
    return ids


def faulty(run, fault, eps=0.0, seed=1, N=300):
    fresh(run, seed, N)
    ids = ids_of(run)
    t = choose_targets(ids, seed, fault, n_targets(fault, eps, N))
    migrate(run, hooks=migration_hooks(fault, t, seed, N))
    build_bundle(run)
    return t


# ------------------------------------------------------------- Merkle --------
def test_inclusion_proofs_all_sizes(tmp_path):
    for n in list(range(1, 66)) + [255, 256, 257]:
        leaves = [derive_bytes(n, "leaf", i, 83) for i in range(n)]
        lv = build_levels(leaves)
        root = merkle_root(leaves)
        assert lv[-1][0] == root
        write_nodes(tmp_path / "t.bin", lv)
        assert read_nodes(tmp_path / "t.bin", lv[0]) == lv
        for i in range(n):
            pr = inclusion_proof(lv, i)
            assert verify_inclusion(leaves[i], pr, root)
            assert not verify_inclusion(bytes([leaves[i][0] ^ 1]) + leaves[i][1:], pr, root)


def test_stored_tree_costs_about_32_bytes_per_record(tmp_path):
    run = tmp_path / "r"
    build(RunConfig(seed=1, N=1000, size=200, tau=128), run)
    per = (run / "merkle_nodes.bin").stat().st_size / 1000
    assert 31 < per < 33


# ------------------------------------------------------------- faults --------
def test_targets_deterministic_and_counted():
    ids = [derive_bytes(1, "id", i, 16) for i in range(10_000)]
    a = choose_targets(ids, 5, "F5", 7)
    assert a == choose_targets(ids, 5, "F5", 7)
    assert a != choose_targets(ids, 6, "F5", 7)
    assert len(set(a)) == 7
    assert [n_targets("F5", e, 10_000) for e in (0.001, 0.01, 0.05)] == [10, 100, 500]
    assert n_targets("F5c", 0, 10_000) == 2 and n_targets("F0", 0, 10_000) == 0
    with pytest.raises(ValueError):
        n_targets("F2", 0.01, 10_000)


def test_manifest_lives_in_private(tmp_path):
    write_manifest(tmp_path, "F0", 0.0, 1, [])
    assert (tmp_path / "private" / "fault_manifest.json").exists()
    assert read_manifest(tmp_path)["fault"] == "F0"


def test_F3_flips_exactly_one_bit(tmp_path):
    run = tmp_path / "r"
    build(RunConfig(seed=2, N=300, size=200, tau=128), run)
    t = choose_targets(ids_of(run), 2, "F3", 1)
    s = Store(run / "store", readonly=True); before = s.get_payload(t[0])[1]; s.close()
    apply_posthoc(run, "F3", t, 2)
    s = Store(run / "store", readonly=True); after = s.get_payload(t[0])[1]; s.close()
    diff = sum(bin(x ^ y).count("1") for x, y in zip(before, after))
    assert diff == 1


# ------------------------------------------------------------- V1 ------------
def test_mini_RQ4_F1b_follows_textbook_F5_is_flat_zero(tmp_path):
    """The RQ4 figure in miniature (P2 / Corollary 1.1)."""
    N, k, B = 2000, 50, 300
    res = {}
    for fault in ("F1b", "F5"):
        run = tmp_path / fault
        t = faulty(run, fault, eps=0.01, seed=21, N=N)
        ff = first_failures(run, list(range(B)), k)
        res[fault] = sum(1 for x in ff if x is not None and x <= k)
        theory = 1 - (1 - len(t) / N) ** k
    lo, hi = wilson(res["F1b"], B)
    assert lo <= theory <= hi, (res["F1b"] / B, theory, lo, hi)
    assert res["F5"] == 0                  # not "low": exactly zero


def test_V1S_reads_only_k_records(tmp_path):
    run = tmp_path / "r"
    build(RunConfig(seed=3, N=500, size=200, tau=128), run)
    p = Prover(run)
    v = verify_sampling(run, k=37, beacon=4, prover=p)
    assert v.verdict == "PASS" and p.reads == 37
    p.close()


def test_V1S_catches_F1a_by_count_even_at_k1(tmp_path):
    run = tmp_path / "r"
    faulty(run, "F1a", seed=4)
    v = verify_sampling(run, k=1, beacon=0)
    assert v.verdict == "FAIL" and any("receipt count" in n for n in v.notes)


def test_V1_cumulative_equals_V0_on_F5(tmp_path):
    run = tmp_path / "r"
    faulty(run, "F5", seed=5)
    assert verify_cumulative(run).verdict == v0_verify(run).verdict == "PASS"


# ------------------------------------------------------------- scoring -------
def _v(verdict, flagged=(), flipped=None):
    return {"verdict": verdict, "flagged": {f: ["x"] for f in flagged}, "flipped": flipped}


def test_scoring_rules():
    m = {"fault": "F5", "eps": 0.0, "seed": 1, "targets": ["aa"]}
    assert detected("F5", _v("FAIL", ["aa"]), m)[0] == 1
    assert detected("F5", _v("FAIL", ["bb"]), m)[0] == 0     # innocent-only FAIL is NOT detection
    assert detected("F5", _v("PASS"), m)[0] == 0
    assert detected("F0", _v("FAIL", ["bb"]), {**m, "fault": "F0", "targets": []})[0] == 0
    m6 = {"fault": "F6", "eps": 0.0, "seed": 1, "targets": [], "expected_flipped": ["a", "b"]}
    assert detected("F6", _v("INCOMPLETE", flipped=["a", "b"]), m6)[0] == 1
    assert detected("F6", _v("INCOMPLETE", flipped=["a"]), m6)[0] == 0      # off by one -> 0
    assert detected("F6", _v("PASS"), m6)[0] == 0
    assert detected("F4m", _v("FAIL"), {**m, "fault": "F4m", "targets": []})[0] == 1
    assert detected("F7", _v("UNRUNNABLE"), {**m, "fault": "F7"})[0] == 0


def test_ground_truth_conflict_stops():
    m = {"fault": "F5", "eps": 0.0, "seed": 1, "targets": ["aa"]}
    cross_check(m, {"flagged": {"aa": ["t"]}})
    with pytest.raises(GroundTruthConflict):
        cross_check(m, {"flagged": {}})


def test_wilson_is_sane():
    lo, hi = wilson(0, 1000)
    assert lo == 0 and hi < 0.005
    lo, hi = wilson(500, 1000)
    assert lo < 0.5 < hi


# ------------------------------------------------------------- isolation -----
ROLES = ["structural", "v1", "v2minus-key", "v2-key", "v3"]


@pytest.fixture(scope="module")
def iso_run(tmp_path_factory):
    from akm.keys_stage import stage_keys
    run = tmp_path_factory.mktemp("iso") / "r"
    build(RunConfig(seed=1, N=200, size=200, tau=128), run)
    stage_keys(run)
    write_manifest(run, "F0", 0.0, 1, [])
    return run


@pytest.mark.parametrize("role", ROLES)
def test_isolation_guard_zero_leaks_and_control_finds_leaks(iso_run, role):
    probe = [sys.executable, "-m", "akm.isolation_probe", "--role", role, "--run", str(iso_run)]
    assert subprocess.run(probe, capture_output=True).returncode == 0
    assert subprocess.run(probe + ["--no-guard"], capture_output=True).returncode > 0


def test_isolated_verification_honest_and_F7(iso_run):
    from akm.isolated import verify_isolated
    v = verify_isolated(iso_run, save=False)
    assert {n: d["verdict"] for n, d in v.items()} == {n: "PASS" for n in v}
    v7 = verify_isolated(iso_run, verifiers=("V2minus", "V2"), keyset="f7", save=False)
    assert v7["V2minus"]["verdict"] == "UNRUNNABLE" and v7["V2"]["verdict"] == "PASS"


# ------------------------------------------------------------- E1 smoke ------
def test_E1_smoke_matrix_passes_gate_2(tmp_path):
    out = tmp_path / "smoke"
    r = subprocess.run([sys.executable, "-m", "akm.run", "e1", "--seeds", "1-1", "--N", "200",
                        "--size", "200", "--out", str(out), "--smoke"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-1500:]
    s = subprocess.run([sys.executable, "-m", "akm.run", "summarize", str(out / "scores.csv")],
                       capture_output=True, text=True).stdout
    assert s.count("[PASS]") == 5 and "[FAIL]" not in s, s


def test_E1_refuses_without_prereg(tmp_path):
    r = subprocess.run([sys.executable, "-m", "akm.run", "e1", "--seeds", "1-1", "--N", "200",
                        "--size", "200", "--out", str(tmp_path / "x")],
                       capture_output=True, text=True, cwd=tmp_path,
                       env={**__import__("os").environ, "PYTHONPATH": str(Path(__file__).parents[1])})
    assert r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr)
