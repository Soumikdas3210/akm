"""Day 3 tests: RQ4 sweep, Experiment 2 cost driver.  python -m pytest -v tests/test_day3.py"""
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from akm.config import RunConfig
from akm.exp_e2 import reset_migration
from akm.exp_rq4 import K_LIST, summarize as rq4_summary
from akm.exp_e2 import summarize as e2_summary
from akm.inventory import build_inventory
from akm.merkle import build_bundle
from akm.migrate import migrate
from akm.pipeline import build
from akm.provision import provision
from akm.store import Store
from akm.verifiers.v1 import challenge_traces, first_failures

ROOT = Path(__file__).parents[1]


def _run(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "akm.run", *args], capture_output=True, text=True,
                          cwd=cwd, env={**os.environ, "PYTHONPATH": str(ROOT)})


def _state(run):
    s = Store(run / "store", readonly=True, need_payload=False)
    rows = list(s.wraps.execute("SELECT id, w_new, epoch FROM wraps ORDER BY id"))
    s.close()
    return hashlib.sha256(repr(rows).encode() + (run / "receipts.bin").read_bytes()).hexdigest()


def test_reset_then_remigrate_is_identical(tmp_path):
    """E2 reps run on a reset store: it must reproduce the fresh migration exactly."""
    run = tmp_path / "r"
    cfg = RunConfig(seed=4, N=300, size=200, tau=128)
    provision(cfg, run, write_corpus=False)
    build_inventory(run)
    migrate(run)
    first = _state(run)
    reset_migration(run)
    s = Store(run / "store", readonly=True, need_payload=False)
    assert all(s.get_wrap(r)[1] is None and s.get_wrap(r)[3] == 0 for r in s.iter_ids())
    s.close()
    assert not (run / "receipts.bin").exists()
    migrate(run)
    assert _state(run) == first


def test_provision_without_corpus(tmp_path):
    cfg = RunConfig(seed=1, N=50, size=200, tau=128)
    provision(cfg, tmp_path, write_corpus=False)
    assert not (tmp_path / "corpus.db").exists()


def test_bench_reports_sane_numbers(tmp_path):
    run = tmp_path / "r"
    cfg = RunConfig(seed=2, N=300, size=200, tau=128)
    provision(cfg, run, write_corpus=False)
    build_inventory(run)
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    for args in (["migrate", "--run", str(run), "--fsync", "group:100", "--proof", "receipts"],
                 ["verify", "--run", str(run), "--verifier", "V2"]):
        p = subprocess.run([sys.executable, "-m", "akm.bench", *args], capture_output=True,
                           text=True, env=env)
        r = json.loads(p.stdout.strip().splitlines()[-1])
        assert r["ok"] and r["wall_s"] > 0 and r["cpu_s"] >= 0 and r["peak_rss_mb"] > 10


def test_traces_agree_with_first_failures(tmp_path):
    from akm.faults import choose_targets, migration_hooks
    run = tmp_path / "r"
    cfg = RunConfig(seed=9, N=500, size=200, tau=128, fsync_policy="group:100")
    provision(cfg, run, write_corpus=False)
    build_inventory(run)
    s = Store(run / "store", readonly=True, need_payload=False); ids = s.iter_ids(); s.close()
    t = choose_targets(ids, 9, "F1b", 25)
    migrate(run, hooks=migration_hooks("F1b", t, 9, 500))
    build_bundle(run)
    beacons = list(range(40))
    ff = first_failures(run, beacons, 100)
    _, traces = challenge_traces(run, beacons, 100)
    for pos, tr in zip(ff, traces):
        first = next((j + 1 for j, (_, bad) in enumerate(tr) if bad), None)
        assert first == pos


def test_rq4_smoke_end_to_end(tmp_path):
    out = tmp_path / "rq4"
    r = _run("rq4", "--out", str(out), "--smoke", "--corpora", "1", "--beacons", "6",
             "--N", "500", "--fsync", "group:100")
    assert r.returncode == 0, r.stderr[-1500:]
    rows = list(csv.DictReader(open(out / "scores.csv")))
    assert len(rows) == 3 * 3 * len(K_LIST) * 6
    assert all(r["mode"] == "sampling" and r["verifier"] == "V1" for r in rows)
    assert all(int(r["fp"]) == 0 for r in rows)                        # never an innocent flag
    assert all(int(r["detected"]) == 0 for r in rows if r["fault"] == "F5")   # Cor. 1.1
    res = rq4_summary(out / "scores.csv", quiet=True)
    assert res["f5_nonzero"] == [] and res["fpfn"]["F1b"] == [0, 0]
    # resume: rerun changes nothing
    before = (out / "scores.csv").read_bytes()
    _run("rq4", "--out", str(out), "--smoke", "--corpora", "1", "--beacons", "6", "--N", "500")
    assert (out / "scores.csv").read_bytes() == before


def test_e2_smoke_end_to_end(tmp_path):
    out = tmp_path / "e2"
    r = _run("e2", "--out", str(out), "--smoke", "--Ns", "300", "--sizes", "200", "--reps", "2")
    assert r.returncode == 0, r.stderr[-1500:]
    t = list(csv.DictReader(open(out / "timings.csv")))
    assert len(t) == 2 * 2 * 2 + 2 * 4          # policies x reps x {none,proof} + reps x 4 verifiers
    assert {x["rep"] for x in t} == {"1", "2"}  # warm-up (rep 0) never written
    assert {x["verifier"] for x in t if x["phase"] == "migrate"} == {"none", "proof"}
    assert all(x["fsync_policy"] == "-" for x in t if x["phase"] == "verify")
    st = {(x["verifier"], x["tau"]): x for x in csv.DictReader(open(out / "storage.csv"))}
    assert float(st[("V0", "128")]["receipt_bytes_per_rec"]) == 83.0
    assert float(st[("V0", "128")]["merkle_bytes_per_rec"]) == 0.0       # V0 recomputes the root
    assert 31 < float(st[("V1", "128")]["merkle_bytes_per_rec"]) < 33    # only V1 stores the tree
    assert float(st[("V2", "128")]["tuple_bytes_per_rec"]) == 16.0
    assert [float(st[("V2", t)]["tuple_bytes_per_rec"]) for t in ("64", "96", "256")] == [8, 12, 32]
    assert e2_summary(out, quiet=True)["p7_fail"] == []


def test_rq4_and_e2_refuse_without_prereg(tmp_path):
    for args in (["rq4", "--out", str(tmp_path / "a"), "--corpora", "1"],
                 ["e2", "--out", str(tmp_path / "b"), "--Ns", "300", "--sizes", "200"]):
        r = _run(*args, cwd=tmp_path)
        assert r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr)
