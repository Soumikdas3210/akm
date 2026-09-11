# Pre-Registration — AKM Project (Group 01, COE4232)

Committed before any experiment run. Author: Soumik (Member A, Experiment Lead).

## 1. Configuration

**Experiment 1 (detection):** N = 10,000 records, 2,048-byte payload, τ = 128,
k = 100 challenges for V1, 100 seeds. Fsync policy: per-record for fault F6
only; group commit (B = 1000) for all other faults, since detection does not
depend on disk durability, only crash-safety (F6) does.

**RQ4 sweep (sampling):** N = 10,000 records, 200-byte payload, 50 corpora ×
20 beacons per corpus (1,000 trials per cell), k ∈ {1, 5, 10, 25, 50, 100,
200, 500}, corruption fractions ε ∈ {0.1%, 1%, 5%}.

**Experiment 2 (cost):** N ∈ {1,000; 10,000; 100,000} × payload ∈ {200 B,
2,048 B, 32,768 B}, 1 discarded warm-up + 5 measured repetitions per cell,
both fsync policies, migration with and without proof generation.

## 2. Fault list and injection points

| Fault | Description | Injected |
|---|---|---|
| F0 | Honest control, no fault | — |
| F1a | Record skipped, no receipt written | during migration |
| F1b | Record skipped, fake success receipt written | during migration |
| F2 | Receipt duplicated | during migration |
| F3 | Ciphertext bit-flipped after migration | post-hoc |
| F4r | One byte of a receipt edited | post-hoc |
| F4m | Signed Merkle root edited | post-hoc |
| F5 | Record sealed with a well-formed WRONG key | during migration, between unwrap and rewrap |
| F5b | Record sealed with a garbage (invalid) wrap | during migration, after self-check |
| F5c | Two records' keys swapped with each other | during migration |
| F6 | Migrator process killed mid-migration | during migration, at the receipt/flip boundary |
| F7 | Old master key retired before verification | at verification time |

## 3. Scoring rules

- **F0:** any verifier reporting FAIL counts as a false positive.
- **F1a, F1b, F2, F3, F5, F5b, F5c:** detected only if the verifier reports
  FAIL **and** correctly names at least one truly damaged record. A FAIL
  naming only innocent records does not count as detection.
- **F4r, F4m:** detected if the verifier reports FAIL (these are global
  faults with no single damaged record to name).
- **F6:** detected only if the verifier reports INCOMPLETE and names the
  *exact* set of records actually migrated before the crash — not PASS,
  and not an approximate set.
- **F7:** detected if the verifier can run at all and still names the
  damaged record from the underlying F5 fault.

## 4. Predicted results — Experiment 1

- **V0 and V1** (no keys): 100% detection on F1a, F1b, F2, F3, F4r, F4m, F6.
  **0% detection on F5, F5b, F5c** (Proposition 1: a keyless check cannot
  tell a wrong key from a right one).
- **V2⁻ and V2** (hold keys): 100% detection on every fault above, **and**
  on F5, F5b, F5c.
- **F7 is the only row where V2⁻ and V2 differ:** V2⁻ becomes UNRUNNABLE
  once the old key is retired; V2 still detects the fault, since it only
  ever needed the new key plus a fingerprint installed at provisioning time.
- **V3** (the oracle): 100% detection everywhere; used only to validate the
  other verifiers, cross-checked against the independent fault manifest on
  every trial.
- **Zero false positives** for every verifier on the F0 (honest) row.

## 5. Predicted results — RQ4 (sampling)

- On F1b and F3 (structural faults), V1-S detection should follow the
  textbook formula 1 − (1 − ε)^k within a 95% Wilson confidence interval.
- On F5 (wrong-key faults), V1-S should detect **0% at every k and every
  ε** — sampling more does not help when there is nothing a keyless check
  can compare against (Corollary 1.1).
- **Decision rule (avoids a known statistical trap):** because 48 F1b/F3
  cells share correlated challenge sequences, testing each at a plain 95%
  interval would produce a small number of "failures" purely by chance
  even if the underlying theory is exactly correct. The pass/fail decision
  therefore uses a Bonferroni-adjusted interval (α = 0.05 / 48) instead of
  a plain per-cell interval. This is decided here, before any RQ4 data
  exists, specifically to avoid that trap.

## 6. Predicted results — Experiment 2 (cost)

- **P4 (verification cost prediction):** V2's verification time will be
  under 10% of migration time **only when migration uses per-record fsync
  and time is measured in wall-clock seconds** — because fsync dominates
  migration time in that case. Under group commit, or measured in CPU
  time, verification is expected to be a substantial fraction of migration
  time, likely exceeding 10%. Both outcomes will be reported as measured,
  not adjusted to fit a single expected number.
- **P7 (storage prediction):** the receipt log (83 bytes/record, fixed
  format) will cost more storage than the commitment fingerprint (τ/8
  bytes/record) at every τ ≤ 128 tested. The fingerprint — the part that
  actually catches wrong-key faults — is predicted to be the cheapest
  component of the whole audit.

## 7. What happens if a prediction fails

Any prediction that does not hold will be reported as a finding in the
Results section, with an explanation, and will not be re-run in an attempt
to make it pass. The only exception is a discovered bug in the harness
itself (verified by disagreement between V3 and the independent fault
manifest) — in that case the whole affected experiment is re-run in full,
never only the failing cells, and the fix is documented.
