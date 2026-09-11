"""
Paper tables, generated straight from the result files.

    python -m akm.run report --results results

Writes results/REPORT.md (every table + key numbers in plain text) and
results/tables/T1_detection.tex ... T6_setup.tex (LaTeX, booktabs).

Why generate instead of copy: hand-copied numbers are the most common source
of error in results sections, and if anything is ever rerun, one command
regenerates every table. All aggregation is shared with the terminal
summaries (akm/analysis.py, exp_rq4.rq4_cells, exp_e2.summarize), so the
report can never disagree with them. Missing experiments are reported as
"not available" rather than crashing.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

from .analysis import VERIFIERS, e1_aggregate, e1_gate2
from .score import wilson

MD_NAME = {"V0": "V0", "V1": "V1", "V2minus": "V2⁻", "V2": "V2", "V3": "V3", "V1S": "V1-S"}
TEX_NAME = {"V0": "V0", "V1": "V1", "V2minus": "V2$^{-}$", "V2": "V2", "V3": "V3", "V1S": "V1-S"}
REPORT_K = 100


def _tex_escape(s: str) -> str:
    return s.replace("%", r"\%").replace("_", r"\_").replace("≥", r"$\geq$").replace("<", r"$<$")


def _tex_table(caption: str, label: str, header: list[str], rows: list[list[str]], align: str,
               wide: bool = False) -> str:
    """wide=True: spans both columns in two-column layouts (table*) and is scaled to
    the text width (needs \\usepackage{graphicx}). Used for tables with many columns."""
    body = "\n".join("    " + " & ".join(r) + r" \\" for r in rows)
    env = "table*" if wide else "table"
    tab = (f"  \\begin{{tabular}}{{{align}}}\n    \\toprule\n    {' & '.join(header)} \\\\\n"
           f"    \\midrule\n{body}\n    \\bottomrule\n  \\end{{tabular}}")
    if wide:
        tab = "  \\resizebox{\\textwidth}{!}{%\n" + tab + "}"
    return (f"\\begin{{{env}}}[t]\n  \\centering\n  \\caption{{{caption}}}\n  \\label{{{label}}}\n"
            f"{tab}\n\\end{{{env}}}\n")


def _md_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


# ------------------------------------------------------------------ T1 -------
def t1_detection(csv_path: Path):
    agg = e1_aggregate(csv_path)
    md_rows, tex_rows = [], []
    n_trials = 0
    for lab in agg["labels"]:
        md, tx = [lab.replace("@", " @ ε=")], [_tex_escape(lab.replace("@", " @ $\\varepsilon$="))]
        for v in VERIFIERS:
            d, n = agg["cells"].get((lab, v), (0, 0))
            if lab == "F0":
                a, m = agg["fp"].get(v, (0, 0))
                cell = f"FP {a}/{m}" if m else "n/a"
                n_trials = max(n_trials, m)
            else:
                cell = f"{100 * d / n:.0f}%" if n else "n/a"
            md.append(cell)
            tx.append(_tex_escape(cell))
        md_rows.append(md)
        tex_rows.append(tx)
    gate = e1_gate2(agg)
    header = ["Fault"] + [MD_NAME[v] for v in VERIFIERS]
    tex = _tex_table(f"Experiment 1: detection rate per fault and verifier ({n_trials} seeds per cell; "
                     "F0 row shows false positives).", "tab:e1", ["Fault"] + [TEX_NAME[v] for v in VERIFIERS],
                     tex_rows, "l" + "r" * len(VERIFIERS))
    return _md_table(header, md_rows), tex, agg, gate, n_trials


# ------------------------------------------------------------------ T2 -------
def t2_rq4(csv_path: Path):
    from .exp_rq4 import rq4_cells, summarize, theory
    cells, N_of, fpfn = rq4_cells(csv_path)
    res = summarize(csv_path, quiet=True)
    md_rows, tex_rows = [], []
    for (fault, eps, k), (d, n) in sorted(cells.items()):
        if k != REPORT_K:
            continue
        lo, hi = wilson(d, n)
        N = N_of[(fault, eps, k)]
        th = "0 (Cor. 1.1)" if fault == "F5" else f"{theory(eps, N, k):.3f}"
        row = [fault, f"{100 * eps:g}%", str(max(1, round(eps * N))), f"{d / n:.3f}",
               f"[{lo:.3f}, {hi:.3f}]", th, str(n)]
        md_rows.append(row)
        tex_rows.append([_tex_escape(x) for x in row])
    header = ["Fault", "ε", "damaged m", "detected", "95% CI", "theory", "trials"]
    tex = _tex_table(f"RQ4: V1-S detection at $k={REPORT_K}$ (sampling mode). "
                     "Theory: $1-(1-m/N)^k$.", "tab:rq4",
                     ["Fault", r"$\varepsilon$", "$m$", "detected", r"95\% CI", "theory", "trials"],
                     tex_rows, "llrrrrr")
    return _md_table(header, md_rows), tex, res, dict(fpfn)


# ------------------------------------------------------------------ T3/T4 ----
def t3_t4_cost(e2_dir: Path):
    from .exp_e2 import GROUP, _med_iqr, summarize
    t = defaultdict(list)
    for r in csv.DictReader(open(e2_dir / "timings.csv")):
        t[(int(r["N"]), int(r["size"]), r["phase"], r["verifier"], r["fsync_policy"])].append(float(r["wall_s"]))
    configs = sorted({(k[0], k[1]) for k in t})
    cols = [("migrate", "none", "per_record"), ("migrate", "proof", "per_record"),
            ("migrate", "none", GROUP), ("migrate", "proof", GROUP),
            ("verify", "V0", "-"), ("verify", "V1S", "-"), ("verify", "V2minus", "-"), ("verify", "V2", "-")]
    names = ["mig none (fsync/rec)", "mig proof (fsync/rec)", "mig none (group)", "mig proof (group)",
             "V0", "V1-S", "V2⁻", "V2"]
    md_rows, tex_rows = [], []
    for N, size in configs:
        row = [f"{N:,}", str(size)]
        for ph, v, pol in cols:
            xs = t.get((N, size, ph, v, pol))
            if xs:
                m, iqr = _med_iqr(xs)
                row.append(f"{m:.3f} ({iqr:.3f})")
            else:
                row.append("—")
        md_rows.append(row)
        tex_rows.append([x.replace(",", "{,}") for x in row])
    t3_md = _md_table(["N", "size B"] + names, md_rows)
    # Two 6-column LaTeX tables instead of one 10-column table that does not fit a page.
    mig = [r[:2] + r[2:6] for r in tex_rows]
    ver = [r[:2] + r[6:10] for r in tex_rows]
    t3_tex = (_tex_table("Experiment 2: migration wall-clock seconds, median (IQR) over the measured reps.",
                         "tab:e2time", ["$N$", "B", "no proof, rec.", "proof, rec.", "no proof, group",
                                        "proof, group"], mig, "rrrrrr")
              + "\n" +
              _tex_table("Experiment 2: verification wall-clock seconds, median (IQR).", "tab:e2verify",
                         ["$N$", "B", "V0", "V1-S", "V2$^{-}$", "V2"], ver, "rrrrrr"))
    res = summarize(e2_dir, quiet=True)
    p4 = defaultdict(dict)
    for N, size, pol, basis, ratio in res["p4"]:
        p4[(N, size)][(pol, basis)] = ratio
    keys = [("per_record", "wall_s"), ("per_record", "cpu_s"), (GROUP, "wall_s"), (GROUP, "cpu_s")]
    md4, tex4 = [], []
    for (N, size), d in sorted(p4.items()):
        row = [f"{N:,}", str(size)] + [
            (f"{d[k]:.3f}" + (" ✓" if d[k] < 0.10 else " ✗")) if k in d else "—" for k in keys]
        md4.append(row)
        tex4.append([x.replace(",", "{,}").replace(" ✓", r"$^{\ast}$").replace(" ✗", "") for x in row])
    hdr4 = ["N", "size B", "fsync/rec wall", "fsync/rec CPU", "group wall", "group CPU"]
    t4_tex = _tex_table("P4: V2 verification time divided by proof-emitting migration time "
                        "(pre-registered threshold 0.10; $^{\\ast}$ = below 0.10).", "tab:p4",
                        ["$N$", "B", "rec.\\ wall", "rec.\\ CPU", "group wall", "group CPU"], tex4, "rrrrrr")
    return t3_md, t3_tex, _md_table(hdr4, md4), t4_tex, res, p4


# ------------------------------------------------------------------ T5 -------
def t5_storage(e2_dir: Path):
    rows = list(csv.DictReader(open(e2_dir / "storage.csv")))
    best = {}                                     # (size, tau, verifier) -> row with the largest N
    for r in rows:
        k = (int(r["size"]), int(r["tau"]), r["verifier"])
        if k not in best or int(r["N"]) > int(best[k]["N"]):
            best[k] = r
    md_rows, tex_rows = [], []
    for (size, tau, v), r in sorted(best.items(), key=lambda x: (x[0][0], x[0][1], VERIFIERS.index(x[0][2]))):
        row = [str(size), str(tau), MD_NAME[v], f"{float(r['tuple_bytes_per_rec']):.1f}",
               f"{float(r['receipt_bytes_per_rec']):.1f}", f"{float(r['merkle_bytes_per_rec']):.1f}",
               f"{float(r['total_bytes_per_rec']):.1f}", f"{float(r['pct_payload']):.2f}%"]
        md_rows.append(row)
        tex_rows.append([_tex_escape(x) if i != 2 else TEX_NAME[v] for i, x in enumerate(row)])
    hdr = ["size B", "τ", "verifier", "commitment", "receipt log", "stored tree", "total", "% payload"]
    tex = _tex_table("Storage overhead per record (bytes), from real counters.", "tab:storage",
                     ["B", r"$\tau$", "verifier", "commit.", "receipts", "tree", "total", r"\% payload"],
                     tex_rows, "rrlrrrrr")
    return _md_table(hdr, md_rows), tex, best


# ------------------------------------------------------------------ T6 -------
def t6_setup(results: Path):
    envs = {}
    for name in ("e1", "rq4", "e2"):
        p = results / name / "environment.json"
        if p.exists():
            envs[name] = json.loads(p.read_text())
    fields = [("cpu", "CPU"), ("os", "OS"), ("python", "Python"), ("cryptography", "cryptography"),
              ("prereg_commit", "PREREG commit"), ("code_commit", "code commit"), ("smoke", "smoke run?")]
    md_rows, tex_rows = [], []
    for key, label in fields:
        vals = [str(envs[e].get(key, "—"))[:60] for e in envs]
        md_rows.append([label] + vals)
        tex_rows.append([_tex_escape(label)] + [_tex_escape(v[:40]) for v in vals])
    if "e2" in envs and "disk" in envs["e2"]:
        md_rows.append(["disk (E2)", json.dumps(envs["e2"]["disk"])] + [""] * (len(envs) - 1))
    tex = _tex_table("Experimental setup.", "tab:setup", ["Item"] + list(envs), tex_rows,
                     "l" + "l" * len(envs), wide=True)
    return _md_table(["Item"] + list(envs), md_rows), tex, envs


# ------------------------------------------------------------------ main -----
def build_report(results: str | Path) -> Path:
    results = Path(results)
    (results / "tables").mkdir(parents=True, exist_ok=True)
    md = ["# Results report (generated — do not edit by hand)",
          "", "Regenerate with `python -m akm.run report`. Every number below comes from the CSVs.", ""]
    facts = []

    def save(name, tex):
        (results / "tables" / name).write_text(tex)

    e1 = results / "e1" / "scores.csv"
    if e1.exists():
        t1_md, t1_tex, agg, gate, n = t1_detection(e1)
        save("T1_detection.tex", t1_tex)
        md += ["## T1 — Experiment 1: detection matrix", "", t1_md, "", "Quality gate 2:"]
        md += [f"- [{'PASS' if ok else 'FAIL'}] {k}" for k, ok in gate.items()] + [""]
        f5 = [l for l in agg["labels"] if l.startswith("F5")]
        det = lambda l, v: agg["cells"].get((l, v), (0, 0))
        v0_f5 = sum(det(l, "V0")[0] for l in f5), sum(det(l, "V0")[1] for l in f5)
        v2_f5 = sum(det(l, "V2")[0] for l in f5), sum(det(l, "V2")[1] for l in f5)
        fp_tot = sum(a for a, _ in agg["fp"].values()), sum(m for _, m in agg["fp"].values())
        facts += [f"E1: {n} seeds per cell.",
                  f"E1: V0 detected {v0_f5[0]} of {v0_f5[1]} wrong-key trials (F5, F5b, F5c combined); "
                  f"V2 detected {v2_f5[0]} of {v2_f5[1]}.",
                  f"E1: {fp_tot[0]} false positives in {fp_tot[1]} honest (F0) verifier-trials."]
    else:
        md += ["## T1 — Experiment 1", "", "_not available (results/e1/scores.csv missing)_", ""]

    rq = results / "rq4" / "scores.csv"
    if rq.exists():
        t2_md, t2_tex, res, fpfn = t2_rq4(rq)
        save("T2_rq4.tex", t2_tex)
        ok = not res["bonf_misses"] and not res["f5_nonzero"]
        md += [f"## T2 — RQ4: V1-S at k = {REPORT_K}", "", t2_md, "",
               f"- 95% CI misses among F1b/F3 cells (all k): {len(res['misses'])} of {res['checked']} "
               f"(~{0.05 * res['checked']:.1f} expected by chance)",
               f"- Bonferroni-adjusted misses: {len(res['bonf_misses'])}",
               f"- F5 cells with any detection: {len(res['f5_nonzero'])}",
               f"- **P2 (Addendum A1 rule): {'PASS' if ok else 'FAIL'}**", ""]
        f5_passed = fpfn.get("F5", [0, 0])[1]
        facts += [f"RQ4: V1-S directly challenged {f5_passed} wrong-key records (F5) and passed every one.",
                  f"RQ4: innocent records flagged across all trials: "
                  f"{sum(v[0] for v in fpfn.values())}.",
                  f"RQ4: P2 under the pre-registered Bonferroni rule: {'PASS' if ok else 'FAIL'}."]
    else:
        md += ["## T2 — RQ4", "", "_not available (results/rq4/scores.csv missing)_", ""]

    e2 = results / "e2"
    if (e2 / "timings.csv").exists() and (e2 / "storage.csv").exists():
        t3_md, t3_tex, t4_md, t4_tex, res, p4 = t3_t4_cost(e2)
        t5_md, t5_tex, best = t5_storage(e2)
        save("T3_cost.tex", t3_tex)
        save("T4_p4.tex", t4_tex)
        save("T5_storage.tex", t5_tex)
        md += ["## T3 — Experiment 2: wall-clock seconds, median (IQR)", "", t3_md, "",
               "## T4 — P4 ratios (V2 verify ÷ proof migration; ✓ = below 0.10)", "", t4_md, "",
               "## T5 — Storage per record (bytes)", "", t5_md, "",
               f"P7: {'PASS' if not res['p7_fail'] else 'FAIL'} "
               "(receipt log larger than the commitment field at every τ ≤ 128)", ""]
        for pol, basis in (("per_record", "wall_s"), ("per_record", "cpu_s"),
                           ("group:1000", "wall_s"), ("group:1000", "cpu_s")):
            vals = [d[(pol, basis)] for d in p4.values() if (pol, basis) in d]
            if vals:
                facts.append(f"E2: P4 ratio [{pol}, {basis[:-2]}] ranges {min(vals):.3f}–{max(vals):.3f} "
                             f"across {len(vals)} configurations "
                             f"({sum(v < 0.10 for v in vals)} below 0.10).")
        rec = [float(r["receipt_bytes_per_rec"]) for r in best.values()]
        if rec:
            facts.append(f"E2: receipt log = {min(rec):.0f} B/record; commitment = τ/8 = 8–32 B/record.")
    else:
        md += ["## T3–T5 — Experiment 2", "", "_not available (results/e2 CSVs missing)_", ""]

    t6_md, t6_tex, envs = t6_setup(results)
    save("T6_setup.tex", t6_tex)
    md += ["## T6 — Setup", "", t6_md, ""]
    if any(e.get("smoke") for e in envs.values()):
        md.insert(3, "> ⚠️ **At least one result set is a SMOKE run.** Do not quote these numbers in the paper.\n")
    md += ["## Key numbers for the text", ""] + [f"- {f}" for f in facts] + [""]
    out = results / "REPORT.md"
    out.write_text("\n".join(md))
    return out
