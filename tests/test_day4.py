"""Day 4 tests: report, repro-check, freeze.  python -m pytest -v tests/test_day4.py"""
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from akm.analysis import e1_aggregate
from akm.freeze import freeze, verify
from akm.report import build_report
from akm.repro import repro_check

ROOT = Path(__file__).parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def _run(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "akm.run", *args], capture_output=True,
                          text=True, cwd=cwd, env=ENV)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    """A small results tree shaped exactly like the real one (all smoke runs)."""
    res = tmp_path_factory.mktemp("res")
    for args in (["e1", "--seeds", "1-2", "--N", "200", "--size", "200", "--out", str(res / "e1")],
                 ["rq4", "--out", str(res / "rq4"), "--corpora", "1", "--beacons", "4", "--N", "400",
                  "--fsync", "group:100"],
                 ["e2", "--out", str(res / "e2"), "--Ns", "300", "--sizes", "200", "--reps", "1"]):
        r = _run(*args, "--smoke")
        assert r.returncode == 0, r.stderr[-1500:]
    return res


# ------------------------------------------------------------- report --------
def test_report_writes_all_tables(results):
    out = build_report(results)
    text = out.read_text()
    for t in ("T1_detection", "T2_rq4", "T3_cost", "T4_p4", "T5_storage", "T6_setup"):
        tex = (results / "tables" / f"{t}.tex").read_text()
        assert tex.count("\\begin{") == tex.count("\\end{")            # balanced LaTeX
        assert "\\toprule" in tex and "\\bottomrule" in tex
    assert "SMOKE run" in text                                           # never quote smoke numbers
    assert "P2 (Addendum A1 rule): PASS" in text and "P7: PASS" in text
    assert "Key numbers for the text" in text


def test_report_matches_shared_aggregation(results):
    """The paper table and the terminal summary come from one function."""
    build_report(results)
    agg = e1_aggregate(results / "e1" / "scores.csv")
    table = (results / "REPORT.md").read_text()
    f5_row = next(l for l in table.splitlines() if l.startswith("| F5 |"))
    cells = [c.strip() for c in f5_row.strip("|").split("|")]
    for v, cell in zip(["V0", "V1", "V2minus", "V2", "V3"], cells[1:]):
        d, n = agg["cells"][("F5", v)]
        assert cell == f"{100 * d / n:.0f}%"
    assert cells[1] == "0%" and cells[4] == "100%"                       # V0 blind, V2 catches


def test_report_survives_missing_experiments(results, tmp_path):
    only_e1 = tmp_path / "res"
    shutil.copytree(results / "e1", only_e1 / "e1")
    text = build_report(only_e1).read_text()
    assert "T1 — Experiment 1" in text and "not available" in text


def test_summarize_and_report_agree_on_gate(results):
    s = _run("summarize", str(results / "e1" / "scores.csv")).stdout
    build_report(results)
    r = (results / "REPORT.md").read_text()
    assert s.count("[PASS]") == r.count("- [PASS]") == 5


# ------------------------------------------------------------- repro ---------
def test_repro_identical_rerun(results, tmp_path):
    r = _run("e1", "--seeds", "2-2", "--N", "200", "--size", "200", "--out", str(tmp_path / "e1"), "--smoke")
    assert r.returncode == 0
    res = repro_check(results / "e1" / "scores.csv", tmp_path / "e1" / "scores.csv", quiet=True)
    assert res["ok"] and res["compared"] > 50
    assert _run("repro-check", str(results / "e1" / "scores.csv"),
                str(tmp_path / "e1" / "scores.csv")).returncode == 0


def test_repro_catches_one_changed_value(results, tmp_path):
    rows = list(csv.DictReader(open(results / "e1" / "scores.csv")))
    rows[5]["tp"] = str(int(rows[5]["tp"]) + 1)
    p = tmp_path / "t.csv"
    w = csv.DictWriter(open(p, "w", newline=""), fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)
    res = repro_check(results / "e1" / "scores.csv", p, quiet=True)
    assert not res["ok"] and len(res["mismatches"]) == 1
    assert _run("repro-check", str(results / "e1" / "scores.csv"), str(p)).returncode == 1


def test_repro_rejects_rows_not_in_original(results, tmp_path):
    r = _run("e1", "--seeds", "3-3", "--N", "200", "--size", "200", "--out", str(tmp_path / "e1"), "--smoke")
    assert r.returncode == 0
    res = repro_check(results / "e1" / "scores.csv", tmp_path / "e1" / "scores.csv", quiet=True)
    assert not res["ok"] and res["compared"] == 0 and res["missing"]


# ------------------------------------------------------------- freeze --------
def _git_repo(path: Path) -> None:
    for cmd in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", *cmd], cwd=path, check=True)
    (path / "PREREG.md").write_text("# PREREG\n")
    subprocess.run(["git", "add", "PREREG.md"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "prereg"], cwd=path, check=True)


def test_freeze_verify_and_tamper(results, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo(repo)
    shutil.copytree(results, repo / "results")
    build_report(repo / "results")
    assert _run("freeze", "--results", "results", cwd=repo).returncode == 0
    m = json.loads((repo / "results" / "MANIFEST.json").read_text())
    assert m["code_commit"] and len(m["prereg_history"]) == 1
    assert "REPORT.md" in m["files"] and "e1/scores.csv" in m["files"]
    assert "e1/audit" in m["audit_trees"] and m["audit_trees"]["e1/audit"]["files"] > 0
    assert any("SMOKE" in w for w in m["warnings"])
    assert _run("freeze", "--results", "results", "--verify", cwd=repo).returncode == 0
    p = repo / "results" / "e2" / "storage.csv"
    p.write_text(p.read_text().replace("83.0", "32.0", 1))              # "improve" a number
    assert _run("freeze", "--results", "results", "--verify", cwd=repo).returncode == 1
    audit_file = next((repo / "results" / "e1" / "audit").rglob("*.json"))
    audit_file.write_text(audit_file.read_text() + " ")
    r = _run("freeze", "--results", "results", "--verify", cwd=repo)
    assert r.returncode == 1 and "AUDIT FOLDER CHANGED" in r.stdout


def test_freeze_refuses_dirty_prereg_and_non_git(results, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_repo(repo)
    shutil.copytree(results, repo / "results")
    (repo / "PREREG.md").write_text("# PREREG\nedited after the fact\n")
    r = _run("freeze", "--results", "results", cwd=repo)
    assert r.returncode != 0 and "REFUSING" in r.stderr
    assert _run("freeze", "--results", "results", "--allow-dirty", cwd=repo).returncode == 0
    assert json.loads((repo / "results" / "MANIFEST.json").read_text())["code_dirty"] is True
    plain = tmp_path / "plain"
    shutil.copytree(results, plain / "results")
    r = _run("freeze", "--results", "results", cwd=plain)
    assert r.returncode != 0 and "not inside a git repository" in r.stderr


def test_environment_records_code_commit(results):
    env = json.loads((results / "e1" / "environment.json").read_text())
    assert "code_commit" in env and "code_dirty" in env
