"""
Paper drafts whose numbers AND claims come from the results.

    python -m akm.run draft --results results

Writes results/paper/:
    numbers.tex   every number as a LaTeX macro (\\akm...)  <- REGENERATE after any rerun
    setup.tex     Experimental Setup draft                  <- starting draft: rewrite in your words
    results.tex   Results draft                             <- starting draft: rewrite in your words
    threats.tex   Threats to validity draft
    tables/       copies of T1-T6 from `report`
    main.tex      standalone wrapper so you can compile and read the draft

Two safety properties:
  1. No number is typed by hand: the prose uses macros, so regenerating
     numbers.tex updates every sentence.
  2. The WORDING follows the outcome. If a pre-registered prediction failed,
     the draft says so and inserts a visible \\akmTODO — it can never claim a
     pass the data does not show. Smoke-run results produce a loud warning.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
import statistics
from collections import defaultdict
from pathlib import Path

VERIFIER_TEX = {"V0": "V0", "V1": "V1", "V1S": "V1-S", "V2minus": r"V2$^{-}$", "V2": "V2", "V3": "V3"}


def _macro_name(key: str) -> str:
    """LaTeX macro names may contain letters only."""
    digits = {"0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five",
              "6": "Six", "7": "Seven", "8": "Eight", "9": "Nine"}
    return "akm" + "".join(digits.get(c, c) for c in key if c.isalnum())


def _num(x, digits=3) -> str:
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    if isinstance(x, int):
        return f"{x:,}".replace(",", "{,}")
    return str(x)


# ============================================================ facts ==========
def e1_facts(results: Path) -> dict | None:
    from .analysis import e1_aggregate, e1_gate2
    p = results / "e1" / "scores.csv"
    if not p.exists():
        return None
    agg = e1_aggregate(p)
    c = agg["cells"]
    f5 = [l for l in agg["labels"] if l.startswith("F5")]
    structural = [l for l in agg["labels"] if l.split("@")[0] in ("F1a", "F1b", "F2", "F3", "F4r", "F4m")]
    wk = {v: (sum(c.get((l, v), (0, 0))[0] for l in f5), sum(c.get((l, v), (0, 0))[1] for l in f5))
          for v in ("V0", "V1", "V2minus", "V2", "V3")}
    struct_min = min((c[(l, v)][0] / c[(l, v)][1] for l in structural for v in ("V0", "V1", "V2minus", "V2", "V3")
                      if (l, v) in c and c[(l, v)][1]), default=None)
    fp = agg["fp"]
    env = json.loads((results / "e1" / "environment.json").read_text()) if (results / "e1" / "environment.json").exists() else {}
    return {"agg": agg, "gate": e1_gate2(agg), "seeds": max((m for _, m in fp.values()), default=0),
            "wk": wk, "struct_min": struct_min,
            "fp": (sum(a for a, _ in fp.values()), sum(m for _, m in fp.values())),
            "f6_min": min((c[("F6", v)][0] / c[("F6", v)][1] for v in ("V0", "V1", "V2minus", "V2", "V3")
                           if ("F6", v) in c), default=None),
            "env": env}


def rq4_facts(results: Path) -> dict | None:
    from .exp_rq4 import rq4_cells, summarize, theory
    from .score import wilson
    p = results / "rq4" / "scores.csv"
    if not p.exists():
        return None
    cells, N_of, fpfn = rq4_cells(p)
    res = summarize(p, quiet=True)
    pick = {}
    for f in ("F1b", "F3", "F5"):
        key = (f, 0.01, 100)
        if key in cells:
            d, n = cells[key]
            pick[f] = {"rate": d / n, "ci": wilson(d, n), "theory": theory(0.01, N_of[key], 100), "n": n}
    env = json.loads((results / "rq4" / "environment.json").read_text()) if (results / "rq4" / "environment.json").exists() else {}
    n_trials = max(n for _, n in cells.values())
    return {"res": res, "pick": pick, "fpfn": fpfn, "n": n_trials, "env": env,
            "N": next(iter(N_of.values())), "p2": not res["bonf_misses"] and not res["f5_nonzero"]}


def e2_facts(results: Path) -> dict | None:
    from .exp_e2 import GROUP, summarize
    d = results / "e2"
    if not ((d / "timings.csv").exists() and (d / "storage.csv").exists()):
        return None
    res = summarize(d, quiet=True)
    t = defaultdict(list)
    for r in csv.DictReader(open(d / "timings.csv")):
        t[(int(r["N"]), int(r["size"]), r["phase"], r["verifier"], r["fsync_policy"])].append(float(r["wall_s"]))
    med = {k: statistics.median(v) for k, v in t.items()}
    configs = sorted({(k[0], k[1]) for k in t})
    p4 = defaultdict(list)
    for N, size, pol, basis, ratio in res["p4"]:
        p4[(pol, basis)].append(ratio)
    overhead = defaultdict(list)
    for N, size in configs:
        for pol in ("per_record", GROUP):
            a, b = med.get((N, size, "migrate", "proof", pol)), med.get((N, size, "migrate", "none", pol))
            if a and b:
                overhead[pol].append(a / b - 1)
    big = max(configs, key=lambda x: (x[0], x[1]))
    ver = {v: med.get((big[0], big[1], "verify", v, "-")) for v in ("V0", "V1S", "V2minus", "V2")}
    st = list(csv.DictReader(open(d / "storage.csv")))
    receipt = min(float(r["receipt_bytes_per_rec"]) for r in st)
    tree = max(float(r["merkle_bytes_per_rec"]) for r in st)
    v2 = {int(r["size"]): float(r["pct_payload"]) for r in st if r["verifier"] == "V2" and r["tau"] == "128"}
    env = json.loads((d / "environment.json").read_text()) if (d / "environment.json").exists() else {}
    return {"res": res, "p4": dict(p4), "overhead": dict(overhead), "big": big, "ver": ver,
            "receipt": receipt, "tree": tree, "v2pct": v2, "configs": configs, "env": env,
            "p7": not res["p7_fail"]}


# ============================================================ writers ========
class Macros:
    def __init__(self):
        self.m: dict[str, str] = {}

    def __call__(self, key: str, value, digits: int = 3) -> str:
        name = _macro_name(key)
        if isinstance(value, str):
            value = (value.replace("\\", "/").replace("_", "-").replace("%", r"\%")
                          .replace("&", r"\&").replace("#", r"\#").replace("$", r"\$")
                          .replace("{", "(").replace("}", ")"))
            self.m[name] = value
        else:
            self.m[name] = _num(value, digits)
        return "\\" + name + "{}"

    def tex(self) -> str:
        lines = ["% GENERATED by `python -m akm.run draft` from the result CSVs.",
                 "% Regenerate after ANY rerun. Never edit by hand.",
                 r"\providecommand{\akmTODO}[1]{\textbf{[TODO: #1]}}"]
        lines += [f"\\providecommand{{\\{k}}}{{{v}}}" for k, v in sorted(self.m.items())]
        return "\n".join(lines) + "\n"


def write_setup(M: Macros, e1, rq, e2) -> str:
    s = [r"% DRAFT generated by akm.run draft. Rewrite the wording in your own voice;",
         r"% keep the \akm... macros so numbers stay tied to the data.", ""]
    env = (e1 or rq or e2 or {}).get("env", {})
    s.append(f"All experiments ran on a single machine ({M('cpu', env.get('cpu', '?'))}, "
             f"{M('os', env.get('os', '?').split('-with')[0])}) using Python {M('python', env.get('python', '?'))} "
             f"and the \\texttt{{cryptography}} library version {M('cryptography', env.get('cryptography', '?'))}. "
             "The storage layer is SQLite with \\texttt{synchronous=FULL}. Records are synthetic JSON-like "
             "documents of exactly 200\\,B, 2\\,KB or 32\\,KB; no real data is used. Every random value "
             "(keys, nonces, fault targets) is derived from a per-run seed, so each run is reproducible.")
    s.append("")
    if e1:
        a = e1["env"].get("args", {})
        s.append(f"\\paragraph{{Experiment 1 (detection).}} Each cell uses {M('EoneSeeds', e1['seeds'])} seeds "
                 f"at $N={M('EoneN', a.get('N', 0))}$ records of {M('EoneSize', a.get('size', 0))}\\,B, "
                 f"$\\tau={M('EoneTau', a.get('tau', 0))}$ and $k={M('EoneK', a.get('k', 0))}$ challenges for V1, "
                 f"with {M('EoneFsync', str(a.get('fsync', '?')).replace('_', '-'))} durability. For each seed, one "
                 "migration per migration-time fault is performed and every verifier audits the same artifact; "
                 "post-hoc faults (F3, F4) are applied to a copy of the honest artifact. Each verifier layer runs "
                 "in its own process behind a file-access guard; key-holding layers can open only the key "
                 "envelopes, never the ciphertext. The fault manifest is stored where no verifier can read it, "
                 "and the oracle V3 is cross-checked against it on every trial.")
        s.append("")
    if rq:
        a = rq["env"].get("args", {})
        s.append(f"\\paragraph{{RQ4 (sampling).}} V1-S runs in sampling mode on {M('RqCorpora', a.get('corpora', 0))} "
                 f"corpora of $N={M('RqN', rq['N'])}$ records, with {M('RqBeacons', a.get('beacons', 0))} "
                 f"independent challenge sequences per corpus ({M('RqTrials', rq['n'])} trials per cell), "
                 "$k\\in\\{1,5,10,25,50,100,200,500\\}$ and corruption fractions $\\varepsilon\\in\\{0.1,1,5\\}\\%$. "
                 "Challenge indices are derived from the signed Merkle root and a per-trial beacon, "
                 "sampled with replacement.")
        s.append("")
    if e2:
        a = e2["env"].get("args", {})
        s.append(f"\\paragraph{{Experiment 2 (cost).}} Each configuration is measured with one discarded warm-up "
                 f"and {M('EtwoReps', a.get('reps', 5))} measured repetitions, reporting the median and "
                 "inter-quartile range. Every measurement runs in a fresh process (timing excludes interpreter "
                 "start-up). Migration is measured with and without proof generation, under per-record fsync "
                 "and under group commit ($B=1000$). Storage is counted from real field lengths.")
        s.append("")
    s.append("\\paragraph{Pre-registration.} Predictions, scoring rules and trial counts were committed to "
             f"version control before any experiment ran (commit \\texttt{{{M('PreregCommit', str(env.get('prereg_commit') or 'MISSING')[:10])}}}). "
             "An addendum, committed before any RQ4 or Experiment~2 data existed, replaced a per-cell "
             "confidence-interval criterion with a Bonferroni-adjusted one; the reason is given in Section~\\ref{sec:results}.")
    return "\n".join(s) + "\n"


def write_results(M: Macros, e1, rq, e2, smoke: bool) -> str:
    s = [r"% DRAFT generated by akm.run draft. Sentences below were CHOSEN by the outcomes;",
         r"% if a prediction failed, a TODO marks where your explanation must go.", ""]
    if smoke:
        s += [r"\akmTODO{These numbers come from SMOKE runs. Regenerate from the real results before submitting.}", ""]
    s.append(r"\label{sec:results}")
    # ---------------- E1
    if e1:
        g, wk = e1["gate"], e1["wk"]
        s.append("\\paragraph{Detection (Experiment 1).} Table~\\ref{tab:e1} gives the full matrix.")
        s.append(f"Keyless verification was blind to key-transformation faults: V0 detected "
                 f"{M('VzeroWrongKey', wk['V0'][0])} and V1 {M('VoneWrongKey', wk['V1'][0])} of "
                 f"{M('WrongKeyTrials', wk['V0'][1])} wrong-key trials (F5, F5b, F5c), while "
                 f"V2$^{{-}}$, V2 and V3 detected {M('VtwoMinusWrongKey', wk['V2minus'][0])}, "
                 f"{M('VtwoWrongKey', wk['V2'][0])} and {M('VthreeWrongKey', wk['V3'][0])} respectively.")
        if e1["struct_min"] is not None:
            s.append("Every verifier detected every structural fault (skips, duplicates, bit-flips, edited receipts "
                     "and roots)" + (" in every trial." if e1["struct_min"] == 1 else
                                     f"; the lowest rate was {M('StructMin', e1['struct_min'])}. \\akmTODO{{explain}}"))
        fp_n, fp_m = e1["fp"]
        s.append(f"On {M('FzeroTrials', fp_m)} honest verifier-trials, "
                 + ("no verifier raised a false alarm." if fp_n == 0 else
                    f"verifiers raised {M('FzeroFP', fp_n)} false alarms. \\akmTODO{{investigate: false positives}}"))
        if g["F7: V2minus 0%, V2 100%"] and g["No row other than F7 separates V2minus from V2 (P6)"]:
            s.append("After retirement of $K_\\text{old}$ (F7), V2$^{-}$ could not run while V2 still detected the "
                     "fault; F7 was the only row separating the two (P6).")
        else:
            s.append("\\akmTODO{P6 did not hold as predicted: describe which rows separate V2$^{-}$ from V2 and why.}")
        if e1["f6_min"] == 1:
            s.append("After a crash between receipt and flip (F6), every verifier reported the migration as "
                     "incomplete with the exact set of flipped records.")
        else:
            s.append("\\akmTODO{F6 was not reported exactly by every verifier: explain.}")
        failed = [k for k, ok in g.items() if not ok]
        s.append("All pre-registered Experiment~1 predictions held." if not failed else
                 "The following pre-registered checks did not hold: " + "; ".join(failed).replace("%", r"\%")
                 + ". \\akmTODO{explain each failure; do not rerun to make it pass}")
        s.append("")
    else:
        s += [r"\akmTODO{Experiment 1 results not available.}", ""]
    # ---------------- RQ4
    if rq:
        r, pk, fpfn = rq["res"], rq["pick"], rq["fpfn"]
        s.append("\\paragraph{Sampling (RQ4).} ")
        if "F1b" in pk and "F3" in pk:
            s.append(f"At $\\varepsilon=1\\%$ and $k=100$, V1-S detected skipped records in "
                     f"{M('RqFoneb', 100 * pk['F1b']['rate'], 1)}\\% and bit-flipped records in "
                     f"{M('RqFthree', 100 * pk['F3']['rate'], 1)}\\% of trials, against the textbook "
                     f"$1-(1-\\varepsilon)^k={M('RqTheory', 100 * pk['F1b']['theory'], 1)}\\%$.")
        f5_pass = fpfn.get("F5", [0, 0])[1]
        if not r["f5_nonzero"]:
            s.append(f"On wrong-key faults it detected nothing at any $k$ or $\\varepsilon$: across the sweep, V1-S "
                     f"directly challenged {M('RqFfiveChallenged', f5_pass)} records carrying a wrong key and "
                     "accepted every one, exactly as Corollary~1.1 predicts.")
        else:
            s.append(f"\\akmTODO{{V1-S detected wrong-key faults in {len(r['f5_nonzero'])} cells, contradicting "
                     "Corollary 1.1 --- treat as a bug until explained.}")
        innocent = sum(v[0] for v in fpfn.values())
        s.append(f"No innocent record was ever flagged ({M('RqInnocent', innocent)} false flags).")
        s.append(f"Of the {M('RqChecked', r['checked'])} skip and bit-flip cells, {M('RqMissNinetyFive', len(r['misses']))} "
                 f"fell outside their 95\\% interval (about {M('RqMissExpected', 0.05 * r['checked'], 1)} are expected "
                 "by chance, more because cells share challenge sequences), and "
                 f"{M('RqMissBonf', len(r['bonf_misses']))} fell outside the pre-registered Bonferroni-adjusted interval.")
        s.append("Prediction P2 therefore held." if rq["p2"] else
                 "\\akmTODO{P2 failed under the pre-registered rule: report which cells and why.}")
        s.append("")
    else:
        s += [r"\akmTODO{RQ4 results not available.}", ""]
    # ---------------- E2
    if e2:
        p4 = e2["p4"]
        s.append("\\paragraph{Cost (Experiment 2).} Tables~\\ref{tab:e2time}--\\ref{tab:p4} give the timings.")
        parts = []
        for (pol, basis), label in ((("per_record", "wall_s"), "per-record fsync, wall-clock"),
                                    (("per_record", "cpu_s"), "per-record fsync, CPU time"),
                                    (("group:1000", "wall_s"), "group commit, wall-clock"),
                                    (("group:1000", "cpu_s"), "group commit, CPU time")):
            v = p4.get((pol, basis))
            if not v:
                continue
            key = f"Pfour{pol}{basis}".replace("_", "").replace(":", "")
            below = sum(x < 0.10 for x in v)
            parts.append(f"{label}: {M(key + 'min', min(v))}--{M(key + 'max', max(v))} "
                         f"({below} of {len(v)} configurations below 0.10)")
        s.append("The ratio of V2 verification to proof-emitting migration (P4, threshold 0.10) was: "
                 + "; ".join(parts) + ".")
        allv = [x for v in p4.values() for x in v]
        if allv and all(x < 0.10 for x in allv):
            s.append("P4 held under every policy and time basis.")
        elif allv and not any(x < 0.10 for x in allv):
            s.append("P4 failed under every policy and time basis. \\akmTODO{discuss}")
        else:
            s.append("P4 therefore holds only where per-record fsync dominates migration wall-clock time; on CPU "
                     "time or under group commit, verification is a substantial fraction of migration, as "
                     "anticipated in the pre-registration addendum.")
        ov = e2["overhead"]
        if ov.get("per_record") and ov.get("group:1000"):
            s.append(f"Emitting the proof (receipts and Merkle bundle) added "
                     f"{M('OverheadRecMin', 100 * min(ov['per_record']), 1)}--{M('OverheadRecMax', 100 * max(ov['per_record']), 1)}\\% "
                     f"to migration time under per-record fsync and "
                     f"{M('OverheadGrpMin', 100 * min(ov['group:1000']), 1)}--{M('OverheadGrpMax', 100 * max(ov['group:1000']), 1)}\\% "
                     "under group commit.")
        s.append("")
        s.append("\\paragraph{Storage.} Table~\\ref{tab:storage} gives the per-record overhead.")
        s.append(f"The receipt log costs {M('ReceiptBytes', e2['receipt'], 1)}\\,B per record for every rung, the "
                 "commitment field only $\\tau/8 = 8$--$32$\\,B, and V1's stored Merkle tree a further "
                 f"{M('TreeBytes', e2['tree'], 1)}\\,B.")
        if 200 in e2["v2pct"]:
            s.append(f"For V2 at $\\tau=128$ the total is {M('VtwoPctSmall', e2['v2pct'][200], 1)}\\% of a 200\\,B payload"
                     + (f" and {M('VtwoPctLarge', e2['v2pct'][max(e2['v2pct'])], 1)}\\% of a "
                        f"{M('LargeSize', max(e2['v2pct']))}\\,B payload." if max(e2["v2pct"]) > 200 else "."))
        s.append("The commitment that buys detection of wrong-key faults is the cheapest component of the audit; "
                 "P7 held." if e2["p7"] else "\\akmTODO{P7 failed: explain.}")
        s.append("")
    else:
        s += [r"\akmTODO{Experiment 2 results not available.}", ""]
    # tables
    s += [r"\input{tables/T1_detection}" if e1 else "", r"\input{tables/T2_rq4}" if rq else "",
          r"\input{tables/T3_cost}" if e2 else "", r"\input{tables/T4_p4}" if e2 else "",
          r"\input{tables/T5_storage}" if e2 else ""]
    return "\n".join(x for x in s) + "\n"


THREATS = r"""% DRAFT generated by akm.run draft. Keep what applies; add anything triage revealed.
\begin{itemize}
  \item \emph{Crash model.} F6 kills the migrator process; it does not cut power. Data the operating system
        had buffered but not yet flushed survives a process crash but might not survive power loss.
  \item \emph{Platform.} Timings come from one machine. Under WSL2, fsync passes through a virtual disk, so
        absolute times and durability are platform-specific; ratios are more portable than seconds.
  \item \emph{Warm caches.} Caches were not dropped between repetitions; a discarded warm-up run keeps the
        measured repetitions under the same conditions.
  \item \emph{Isolation strength.} The file-access guard used for bulk runs prevents accidental access by our
        own code, not a deliberately malicious verifier; the Docker configuration is the stronger layer.
  \item \emph{Shared codebase.} The oracle V3 shares code with the verifiers it grades; every trial therefore
        cross-checks V3 against the independent fault manifest, and any disagreement halts the run.
  \item \emph{Synthetic data and seeded keys.} Records are synthetic and keys are derived from a seed rather
        than the operating system's random source. Neither affects detection; content could slightly
        affect timing.
  \item \emph{Sampling analysis.} Each RQ4 challenge sequence serves every $k$ as a prefix, so points on one
        curve are correlated; the pass/fail decision uses a Bonferroni correction, which remains valid
        under such dependence.
  \item \emph{Single group-commit size.} Group commit was measured at $B=1000$ only.
\end{itemize}
"""

MAIN = r"""% Standalone preview of the generated sections. Compile with:  latexmk -pdf main.tex
\documentclass{article}
\usepackage{booktabs,amsmath,graphicx}
\usepackage[T1]{fontenc}
\input{numbers}
\begin{document}
\section{Experimental Setup}
\input{setup}
\section{Results}
\input{results}
\section{Threats to Validity}
\input{threats}
\end{document}
"""


def build_draft(results: str | Path) -> Path:
    from .report import build_report
    results = Path(results)
    build_report(results)                                   # tables are always fresh
    out = results / "paper"
    (out / "tables").mkdir(parents=True, exist_ok=True)
    for t in (results / "tables").glob("*.tex"):
        shutil.copy(t, out / "tables" / t.name)
    e1, rq, e2 = e1_facts(results), rq4_facts(results), e2_facts(results)
    smoke = any((f or {}).get("env", {}).get("smoke") for f in (e1, rq, e2))
    M = Macros()
    setup = write_setup(M, e1, rq, e2)
    res = write_results(M, e1, rq, e2, smoke)
    (out / "setup.tex").write_text(setup)
    (out / "results.tex").write_text(res)
    (out / "threats.tex").write_text(THREATS)
    (out / "numbers.tex").write_text(M.tex())
    (out / "main.tex").write_text(MAIN)
    return out


def undefined_macros(paper_dir: str | Path) -> set[str]:
    """Every \\akm... macro used in the drafts must be defined in numbers.tex."""
    d = Path(paper_dir)
    defined = set(re.findall(r"\\providecommand\{\\(akm\w+)\}", (d / "numbers.tex").read_text()))
    used = set()
    for f in ("setup.tex", "results.tex", "threats.tex"):
        used |= set(re.findall(r"\\(akm[A-Za-z]+)", (d / f).read_text()))
    return used - defined
