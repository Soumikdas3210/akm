"""Day 5 tests: paper drafts and the live demo.  python -m pytest -v tests/test_day5.py"""
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from akm.draft import build_draft, undefined_macros

ROOT = Path(__file__).parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT)}
HAVE_LATEX = shutil.which("pdflatex") is not None


def _run(*args):
    return subprocess.run([sys.executable, "-m", "akm.run", *args], capture_output=True, text=True, env=ENV)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    res = tmp_path_factory.mktemp("res")
    for args in (["e1", "--seeds", "1-2", "--N", "200", "--size", "200", "--out", str(res / "e1")],
                 ["rq4", "--out", str(res / "rq4"), "--corpora", "1", "--beacons", "4", "--N", "400",
                  "--fsync", "group:100"],
                 ["e2", "--out", str(res / "e2"), "--Ns", "300", "--sizes", "200", "--reps", "1"]):
        r = _run(*args, "--smoke")
        assert r.returncode == 0, r.stderr[-1500:]
    return res


def _compile(paper: Path) -> str:
    for _ in range(2):                                           # twice, for references
        subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
                       cwd=paper, capture_output=True, timeout=120)
    return (paper / "main.log").read_text(errors="replace")


def _copy(results: Path, dest: Path) -> Path:
    shutil.copytree(results, dest, ignore=shutil.ignore_patterns("paper", "tables", "REPORT.md"))
    return dest


# ------------------------------------------------------------- draft ---------
def test_draft_files_and_macros(results):
    paper = build_draft(results)
    for f in ("numbers.tex", "setup.tex", "results.tex", "threats.tex", "main.tex",
              "tables/T1_detection.tex", "tables/T3_cost.tex"):
        assert (paper / f).exists(), f
    assert undefined_macros(paper) == set()
    assert "tab:e2verify" in (paper / "tables" / "T3_cost.tex").read_text()   # split, not squeezed


@pytest.mark.skipif(not HAVE_LATEX, reason="pdflatex not installed")
def test_draft_compiles_cleanly(results):
    paper = build_draft(results)
    log = _compile(paper)
    assert (paper / "main.pdf").exists()
    assert "Undefined control sequence" not in log
    assert "LaTeX Warning: Reference" not in log                   # every \ref resolves
    assert not any(l.startswith("!") for l in log.splitlines())
    worst = max([float(x.split("pt")[0]) for x in log.split("Overfull \\hbox (")[1:]] or [0])
    assert worst < 5, f"a table or line overflows the page by {worst}pt"


def test_honest_outcome_sentences(results):
    text = (build_draft(results) / "results.tex").read_text()
    assert "All pre-registered Experiment~1 predictions held." in text
    assert "Prediction P2 therefore held." in text
    assert "SMOKE" in text                                          # smoke warning is visible


def test_failed_prediction_is_never_claimed(results, tmp_path):
    """If V0 'detects' an F5 trial, the draft must say a check failed — never 'all held'."""
    res = _copy(results, tmp_path / "res")
    p = res / "e1" / "scores.csv"
    rows = list(csv.DictReader(open(p)))
    for r in rows:
        if r["fault"] == "F5" and r["verifier"] == "V0":
            r["detected"], r["verdict"] = "1", "FAIL"
            break
    w = csv.DictWriter(open(p, "w", newline=""), fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)
    text = (build_draft(res) / "results.tex").read_text()
    assert "All pre-registered Experiment~1 predictions held." not in text
    assert "did not hold" in text and "\\akmTODO{explain each failure" in text


def test_rq4_f5_detection_flags_todo(results, tmp_path):
    res = _copy(results, tmp_path / "res")
    p = res / "rq4" / "scores.csv"
    rows = list(csv.DictReader(open(p)))
    for r in rows:
        if r["fault"] == "F5":
            r["detected"], r["verdict"] = "1", "FAIL"
            break
    w = csv.DictWriter(open(p, "w", newline=""), fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)
    text = (build_draft(res) / "results.tex").read_text()
    assert "contradicting Corollary 1.1" in text and "Prediction P2 therefore held." not in text


@pytest.mark.skipif(not HAVE_LATEX, reason="pdflatex not installed")
def test_draft_with_only_e1_still_compiles(results, tmp_path):
    res = tmp_path / "res"
    shutil.copytree(results / "e1", res / "e1")
    paper = build_draft(res)
    text = (paper / "results.tex").read_text()
    assert "RQ4 results not available" in text and "Experiment 2 results not available" in text
    assert undefined_macros(paper) == set()
    log = _compile(paper)
    assert (paper / "main.pdf").exists() and "Undefined control sequence" not in log


def test_draft_cli(results):
    r = _run("draft", "--results", str(results))
    assert r.returncode == 0 and "wrote" in r.stdout


# ------------------------------------------------------------- demo ----------
def test_demo_tells_the_story():
    from akm.demo import run_demo
    out = run_demo(N=300, pause=0)
    assert out["self_check_aborts"] == 0                            # the migrator's self-check passed
    assert out["V0"] == "PASS" and out["V1_direct"] == "ACCEPTED"   # keyless rungs are blind
    assert out["V2minus"] == "FAIL" and out["V2"] == "FAIL" and out["V2_exact"]
    assert out["V3"] == "FAIL"
    assert out["F7_V2minus"] == "UNRUNNABLE" and out["F7_V2"] == "FAIL"
