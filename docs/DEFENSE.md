# Defense Preparation: Questions You Will Probably Be Asked

Each answer has two parts: **what to say** (in your own words, not memorised), and **Show**, the file, test, or command that proves it. Being able to *show* is what separates understanding the work from having it handed to you. Practise each "Show" at least once before the defense.

**Before the defense:** run `python -m akm.run demo` once, so you've seen its output yourself. It takes 15 seconds and walks through the core result (Q2–Q4) live on real code.

---

## A. The idea

**Q1. What does your project show, in one sentence?**
Checking a key rotation's paperwork, even perfectly, cannot tell you whether each record was sealed with the *right* key. You need a check that holds a key, and only a check with a fingerprint stored in advance keeps working after the old key is thrown away.
*Show:* `python -m akm.run demo`, the summary box at the end.

**Q2. Why can't V0 detect a wrong-key rewrap (F5)?**
A wrap with the wrong key is still a perfectly well-formed 40-byte envelope, and the migrator writes honest receipts about the bytes it actually stored. Everything V0 can check (signatures, the Merkle root, receipts against storage) is consistent. Telling "right key" from "wrong key" needs a key, and V0 has none. That's Proposition 1.
*Show:* demo step 3 (`V0 verdict: PASS`), and `tests/test_day1.py::test_F5_wrong_dek_V0_blind_key_rungs_catch`.

**Q3. Sampling works for data-possession proofs. Why doesn't it help here (RQ4)?**
The textbook formula `1 − (1 − ε)^k` assumes a damaged record is detectable *once you sample it*. That's true for a skipped record or a flipped bit. It's false for a wrong key: sampling the damaged record gives the keyless checker nothing to compare it with. So detection is 0 at every k, not low but zero.
*Show:* demo step 4 (`challenge on the damaged record: ACCEPTED`). In the results, the RQ4 "challenged and passed" count in `REPORT.md` shows how many wrong-key records V1-S looked at directly and accepted.

**Q4. V2⁻ and V2 both catch F5. Why does V2 matter?**
V2⁻ compares the key inside the old envelope with the one inside the new envelope, so it needs the old master key. Once the old key is retired, which is the whole point of rotating, V2⁻ can't run at all (F7). V2 checks against a fingerprint installed at the start, so it only needs the new key.
*Show:* demo step 7; the F7 row of Table T1 is the only row where they differ.

**Q5. Why does the fingerprint include the record ID?**
Without the ID, swapping the keys of two records would leave both fingerprints valid: zero detections. With the ID inside the hash, each record's fingerprint only matches *its own* key, so a swap gives two detections.
*Show:* `tests/test_day1.py::test_F5c_dek_swap_gives_two_mismatches`; the formula in `akm/provision.py` → `commitment()`.

---

## B. Design decisions

**Q6. What is envelope encryption?**
Each record is encrypted with its own small key (DEK); the DEK is encrypted ("wrapped") under a master key (KEK). Rotating the master key only re-wraps the small keys; the big encrypted records never move.
*Show:* the per-record loop in `akm/provision.py`.

**Q7. Why does the receipt get written before the epoch flip?**
So that after a crash, every flipped record already has a durable receipt. The receipts are always a superset of the work done. A crash can leave an extra receipt (harmless), never an un-receipted flipped record. The earlier version had the order reversed.
*Show:* `tests/test_day1.py::test_crash_leaves_describable_state_and_resumes`. Mention that putting the old order back makes exactly the three 6→7 crash tests fail.

**Q8. Why is F5 injected between steps 2 and 3 of Algorithm 1?**
If the wrap were corrupted *after* step 3, the migrator's own self-check (step 4) would catch it and abort the record, so the fault would never reach storage. Swapping the key *before* step 3 means the wrap and the self-check both use the wrong key. That models a real bug: a buggy worker's self-test is buggy too.
*Show:* `Hooks.wrong_dek` in `akm/migrate.py`; demo step 2 (`self-check failures: 0`).

**Q9. Why are there two database files?**
The key-holding checkers must never see encrypted data; otherwise a checker with the new key could decrypt everything. Keeping the key envelopes (`wraps.db`) in a separate file from the ciphertext (`payload.db`) means isolation is enforced by *which file a process can open*, not by a promise.
*Show:* the top comment in `akm/store.py`.

**Q10. How do you know a key-holding checker really couldn't read the ciphertext?**
Two layers. In the bulk runs, every checker runs in its own process with a guard that refuses to open any file not on its allowlist. In the formal test, each checker runs in its own Docker container where forbidden files aren't mounted at all. A probe tries to open every forbidden file; it opens zero with the guard on, and 11–21 files without the guard, which proves the probe really can find leaks.
*Show:* `python -m pytest -q tests/test_day2.py -k isolation`; `results/isolation_docker.txt`.

**Q11. Why a Merkle tree, and why promote odd nodes instead of duplicating them?**
Signing one 32-byte root commits to every receipt at once. With "duplicate the last node", the lists `[a,b,c]` and `[a,b,c,c]` give the same root, which would hide a duplicated receipt (F2). Promotion avoids that, and the leaf/node prefixes stop a leaf from being mistaken for an internal node.
*Show:* `akm/merkle.py`; `tests/test_day1.py::test_V0_catches_F2_duplicate`.

**Q12. Why is a receipt 83 bytes?**
It stores only what can't be recomputed later: the ID, the epoch, the status, the hash of the old envelope (the old envelope may be deleted after retirement), and the leaf hash (to name the bad record, and to detect a torn write after a crash). The hashes of the new envelope and the ciphertext are *recomputed* by the checker, which is precisely how tampering is caught.
*Show:* the table at the top of `akm/receipts.py`.

**Q13. Real systems use true randomness for keys. Why do you derive keys from a seed?**
Reproducibility: the same seed gives a byte-identical run, so anyone can re-run any trial. Detection depends on *whether* a key is right, not on its value, so this doesn't affect the results. It's labelled experiment-only in the code and listed as a threat to validity.
*Show:* `python -m akm.run repro-check ...` output from Day 4 (identical rows).

---

## C. Method

**Q14. What is pre-registration, and isn't your addendum cheating?**
The predictions and scoring rules were committed to git *before* running, so a wrong prediction becomes a finding instead of being quietly adjusted. The addendum was committed *before* any RQ4 or Experiment 2 data existed. It fixed a rule that would have failed even for perfect code (checking 48 correlated cells at 95 % each). Changing a rule before seeing data, and saying why, is how pre-registration is supposed to work; changing it after seeing data would be cheating.
*Show:* `git log -- PREREG.md` (dates); `prereg_history` in `results/MANIFEST.json`.

**Q15. V3 is the ground truth. How do you know V3 itself is right?**
V3 shares code with the checkers it grades, so it isn't trusted alone. On every trial, V3's findings are compared with the saboteur's independent answer key (the fault manifest), and any disagreement stops the entire experiment.
*Show:* `cross_check()` in `akm/score.py`; `tests/test_day2.py::test_ground_truth_conflict_stops`.

**Q16. How do you know your checkers don't just flag everything?**
The F0 row: honest migrations with no faults. Every checker must pass them. Any failure counts as a false alarm, and the table reports the count. Also, the scoring rule refuses to count a FAIL as a detection unless it names at least one truly damaged record.
*Show:* the F0 row of T1; `tests/test_day2.py::test_scoring_rules`.

**Q17. Is 100 seeds enough?**
Most cells are deterministic (a checker either can or can't see a fault), so 100 seeds is about putting a tight bound on them. With 0 detections in 100 trials, the 95 % upper bound on the true rate is **3.7 %**; across the 400 wrong-key trials combined it is **0.95 %**. With 100 of 100, the lower bound is **96.3 %**.
*Show:* `wilson()` in `akm/score.py`.

**Q18. Why the Bonferroni correction?**
Testing 48 cells at 95 % each means about 2–3 miss by chance even when the theory is exact, and the cells share challenge sequences, so misses come in clumps. Bonferroni tests each cell at about 99.9 %, keeping the overall false-alarm rate at 5 %, and it stays valid when the cells are correlated.
*Show:* `rq4-summary` output; Addendum A1.

**Q19. How did you make the timings trustworthy?**
Each measurement runs in a fresh process, so peak memory belongs to that phase alone and start-up time is excluded. One warm-up run is discarded and five are measured. The report gives the median and IQR, because timing distributions have long tails. Hardware and software versions are logged.
*Show:* top comment in `akm/bench.py`; `tests/test_day3.py::test_e2_smoke_end_to_end` (the warm-up is never written).

---

## D. Results

**Q20. P4 failed under group commit. Is your paper wrong?**
No, that was expected and pre-registered (Addendum A4). With per-record fsync, the migration is slow because of disk flushes, so verification looks cheap *relative* to it. On CPU time, or with group commit, verification is a large share. The honest statement is that "verification is cheap" depends on how the migration writes to disk. That's a finding, not an error.
*Show:* Table T4 in `REPORT.md`.

**Q21. Why does V1 in the fault matrix score exactly like V0?**
The ladder is cumulative: V1 runs all of V0's checks first, and V0 already reads every record, so V1's extra challenges can't find anything new. That's why RQ4 uses a separate sampling-only mode, V1-S, which is a cheaper alternative to V0 rather than a step above it.
*Show:* `akm/verifiers/v1.py` top comment; `tests/test_day2.py::test_V1_cumulative_equals_V0_on_F5`.

**Q22. Why does the receipt log cost more than the fingerprint?**
83 bytes per record versus τ/8 = 8–32 bytes. The part of the audit that actually catches wrong keys is the cheapest part (P7).
*Show:* Table T5.

**Q23. A 0 % result looks suspicious. Could it be a bug?**
It could have been, so it was tested three ways:
- the same checker catches skips and bit-flips at exactly the textbook rate, so it works;
- a separate 3,000-trial validation check during development, and the exactness line of the full sweep, both show it never flagged an innocent record and never missed a sampled skipped or bit-flipped record;
- on wrong-key records it passed every single one it challenged.

A broken checker wouldn't show that pattern.
*Show:* the exactness line in `rq4-summary`.

---

## E. Limitations and next steps

**Q24. What are the main limitations?**
- Crashes are process kills, not power loss.
- Timings come from one machine under WSL2, so ratios matter more than seconds.
- Caches are warm.
- The guard stops accidental access, not a malicious checker (Docker is the stronger layer).
- The data is synthetic.
- Only one group-commit size was tested.

*Show:* `results/paper/threats.tex`.

**Q25. What would you do next?**
- Compare the explicit fingerprint with key-committing encryption (RQ3).
- Crash at all three boundaries under concurrency (RQ5).
- Test against a real key manager, such as Vault Transit.

All three are named as future work in the proposal.

---

## F. Process

**Q26. How can someone check that your numbers are real?**
Every result file is checksummed in `results/MANIFEST.json`, tied to a code commit and the pre-registration commits, and released under the `results-v1` tag. `freeze --verify` detects any edited file. `repro-check` shows a fresh clone reproduces the detection results exactly.
*Show:* `python -m akm.run freeze --results results --verify`.

**Q27. How was the code produced?**
Answer truthfully and according to your course's policy on AI assistance. If you used an AI assistant, say so plainly. What the defense tests is whether *you* understand and can reproduce every result, which is what this document and the "Show" commands are for. Check your course's disclosure rules before the defense, and follow them in the paper too.

---

## Practice checklist

- [ ] Run `python -m akm.run demo` and narrate it aloud without reading
- [ ] For Q2, Q7, Q8, Q10 and Q14, explain the answer to a teammate without looking
- [ ] Run each "Show" command once and know where its output appears
- [ ] Open `akm/migrate.py` and point to all seven steps of Algorithm 1 from memory
