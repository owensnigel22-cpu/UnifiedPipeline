# Security Track — Milestone 1: Coverage-guided Fuzzing — Implementation Plan

**Status:** PLANNING ONLY. No code is implemented in this plan. Awaiting ack
before any code is written (per the approved process).

**Scope decision (from approved decisions):** this is milestone 1 of the
security track — *fuzzing only*. The other capabilities (crypto policy, AEAD/KDF
primitives, design note for signing/network) are separate later milestones and
**must not** be batched into this PR. `SECURITY.md` is **not** touched; if any
step here would require amending it, I stop and ask.

**Repository state at planning:** `main = 1073caa`; Python ≥3.11 library; pytest
+ Hypothesis; ruff 0.17.3 + mypy 2.4.1 (baseline 99); 11 CI jobs; vector
provenance pinned in `tests/vectors/SOURCES.json`. No fuzzing infrastructure
exists today.

---

## 1. Scope

Add a coverage-guided fuzzing harness for KeyLab's untrusted-input parsers,
seeded from the existing official vectors, wired into CI as a short per-PR smoke
campaign and an extended nightly campaign, with crashes treated as release
blockers. In-character: these parsers already have Hypothesis property tests;
coverage-guided fuzzing is the natural escalation for byte-level input surfaces.

**In scope**
- Fuzz targets for the six untrusted-input entry points (see §2).
- Seed corpora derived from existing test vectors (§4).
- A `[fuzz]` optional extra adding `atheris` (not a runtime dependency).
- CI: a dedicated ubuntu fuzz job (PR smoke + nightly extended) (§6).
- A seeded-defect "canary" target proving the harness actually catches bugs (§7).

**Out of scope (this milestone)**
- Any change to production code behavior (fuzzing is test-time only).
- Crypto-policy module, AEAD/KDF primitives, signing/network design note
  (later milestones).
- `SECURITY.md` edits.

---

## 2. Fuzz targets (critical input surfaces)

All six accept attacker-controlled bytes/strings and already raise typed errors
on bad input; the fuzzer asserts they never crash with an *unexpected*
exception type (only their documented `ValueError`/`PsbtError`/`TypeError`
families are allowed) and never hang.

| Target | Entry point | Input |
|---|---|---|
| PSBT parse+validate | `keylab.psbt.parse(raw: bytes)` | bytes |
| Transaction parse | `keylab.encoding.transaction.parse_transaction(raw: bytes)` | bytes |
| Bech32 / Bech32m | `keylab.encoding.bech32.decode`, `decode_segwit_address` | str |
| Base58 / Base58Check | `keylab.encoding.base58.b58decode`, `check_decode` | str |
| WIF | `keylab.encoding.wif.decode` | str |
| BIP-39 mnemonic | `keylab.mnemonic.mnemonic_to_entropy`, `is_valid_mnemonic` | str |

Each target wraps the call in a guard that:
- catches the target's **documented** exceptions and returns (expected);
- lets any **undocumented** exception, `MemoryError`, or recursion blow-up
  propagate (a finding);
- for `bytes`-input targets, uses `FuzzedDataProvider` to get raw bytes; for
  `str`-input targets, decodes the fuzz bytes as UTF-8 (surrogatepass) so the
  decoder sees arbitrary text.

---

## 3. Framework choice & platform reality

- **Atheris** (Google's libFuzzer-based coverage-guided fuzzer for Python),
  per the approved dependency decision — an optional `[fuzz]` extra, never a
  runtime dependency.
- **Platform:** Atheris is Linux-first (libFuzzer/clang). It does **not** run
  reliably on Windows, and the local dev machine here is Windows. Therefore:
  - the fuzz **CI job runs on ubuntu only**, on **Python 3.12** (the version the
    repo's non-matrix jobs — lint, full-extras, bench-smoke — already use, so
    Atheris wheel availability is known-good);
  - the existing 8-cell ubuntu/windows × 3.11–3.14 test matrix is **unchanged**;
  - harness modules import `atheris` lazily/guarded so the files lint and
    type-check on all platforms even where Atheris is absent.
- **Determinism in CI:** smoke runs are time-bounded (`-max_total_time`) and/or
  run-bounded (`-runs`) so PR latency is predictable.

---

## 4. Seed corpora & provenance

- Seeds are built from the **existing pinned vectors** — e.g. valid/invalid PSBTs
  from `bip174_psbt_vectors.json`, transactions from `bip143_signing_vectors.json`
  (`unsigned_tx`, `final_tx`) and `bip143_sighash_vectors.json`, bech32 strings
  from `bech32_vectors.json`, plus near-valid mutations.
- **Provenance respected:** seed corpora are *generated from* the already-pinned
  fixtures at fuzz time (a small `fuzz/corpus_seed.py` reads them); no new
  copies of vector data are committed that would need a `SOURCES.json` entry. If
  any standalone seed file is committed, it goes through the same
  `SOURCES.json` + `scripts/vectors.py verify` discipline.
- Both **valid** and **near-valid** seeds are included (near-valid = valid seed
  with single-byte/length mutations), so the fuzzer starts near interesting
  boundaries. Grammar-aware mutation for PSBT (respecting the keytype/record
  framing) is a documented future enhancement, not required for this milestone.

---

## 5. Harness structure (where files live)

```
fuzz/
  __init__.py
  _harness.py            # shared: guarded atheris import, expected-exception sets
  corpus_seed.py         # builds seed corpora from tests/vectors/*
  fuzz_psbt.py           # one @atheris target per surface
  fuzz_transaction.py
  fuzz_bech32.py
  fuzz_base58.py
  fuzz_wif.py
  fuzz_mnemonic.py
  fuzz_canary.py         # seeded-defect target (see §7)
  corpus/<target>/       # generated seed inputs (git-ignored or small committed set)
scripts/
  run_fuzz.py            # entry point: run one/all targets for a bounded time
tests/
  test_fuzz_harness.py   # runs on all platforms; see §7
```

Each `fuzz_*.py` exposes a `TestOneInput(data: bytes)` and an
`if __name__ == "__main__": atheris.Setup(...); atheris.Fuzz()` block, so it runs
both under `scripts/run_fuzz.py` and directly.

---

## 6. CI integration

- **New job `fuzz-smoke`** (ubuntu-latest, Python 3.12), triggered on
  `pull_request` and `push`:
  - install `.[fuzz]` (+ the parsers' own extras as needed);
  - seed corpora via `corpus_seed.py`;
  - run each target for a short bounded budget (e.g. `-max_total_time=30`
    per target, tunable) under `scripts/run_fuzz.py`;
  - **any crash/uncaught exception fails the job** (release blocker).
  - This becomes the **12th CI job**; the existing 11 are unchanged. (I will note
    in the PR that the job count moves 11 → 12 so the "11/11" shorthand in
    reports becomes "12/12" going forward.)
- **New nightly workflow `fuzz-nightly.yml`** (`schedule:` cron, ubuntu):
  extended campaign (minutes per target) over an accumulated corpus; crashes
  open a failing run. Corpus persistence via `actions/cache` or artifact upload
  (documented; no secrets).
- Crashes are **release blockers** per the approved acceptance criteria.

---

## 7. Seeded-defect acceptance demonstration

To prove the harness actually catches defects (acceptance criterion), add
`fuzz/fuzz_canary.py` targeting a **deliberately buggy local toy function**
(defined inside the fuzz module, never in `src/keylab/`): e.g. a mini length-
prefixed parser that indexes out of bounds on a crafted input. Then
`tests/test_fuzz_harness.py`:
- on **Linux with atheris present**, runs the canary target for a bounded budget
  in a subprocess and asserts the harness **reports the planted crash** (non-zero
  exit / crash artifact);
- on **Windows or when atheris is absent**, `skip`s the live-fuzz assertion but
  still imports every `fuzz_*` module and calls each `TestOneInput` on the seed
  corpus directly (pure-Python, no atheris) to prove the targets execute and the
  expected-exception guards hold.

This keeps the suite green cross-platform while proving, on Linux CI, that the
fuzzer finds a known defect. The canary bug lives only in the fuzz tree and is
never shipped in `keylab`.

---

## 8. Dependency change

- Add optional extra `fuzz = ["atheris>=2.3"]` in `pyproject.toml` (exact pin at
  implementation time against the 3.12 Linux wheel). **Not** a runtime or core
  dependency.
- **DEPENDENCY POLICY justification entry** (to include in the PR description):
  wheel availability — Atheris ships Linux wheels for 3.12; Python-version
  support — restricted to the 3.12 ubuntu fuzz job, matrix untouched; OS support
  — Linux-only, Windows explicitly skipped; CI impact — one new bounded ubuntu
  job + one nightly workflow. No new *runtime* dependency; no new core crypto
  lib.

---

## 9. Quality gates (this milestone)

- `fuzz-smoke` green on the PR (bounded campaign, no crashes).
- Existing **11 jobs stay green**; full suite + `validate_all()` = 0 unaffected
  (fuzzing adds no runtime-code change).
- `ruff` clean and `mypy` baseline unchanged or improved on the new `fuzz/` and
  `scripts/run_fuzz.py` (guarded `atheris` import typed/`# type: ignore`d
  minimally; prefer a typed shim over broad ignores).
- `gen_api_docs --check` unaffected (no public `keylab` API added).
- No `SECURITY.md` change; no production-code behavior change.
- Docs: a "How to run the fuzzers" section (README or `docs/`), covering local
  Linux use, the CI smoke/nightly split, and corpus handling.

---

## 10. Risks & mitigations

- **Atheris/Windows & Python 3.14:** mitigated by pinning the fuzz job to ubuntu
  + 3.12 and guarding imports; local Windows dev runs the non-atheris path.
- **Flaky/time-variable campaigns:** bounded budgets + fixed `-seed` for the
  smoke job keep PR runs deterministic; the nightly is the place for longer,
  variable exploration.
- **A real crash surfaced on day one:** if a target crashes on a seeded/near-valid
  input, that is a genuine finding — I stop, report it, and (per gates) it blocks
  until fixed, rather than quietly widening the expected-exception set.
- **Corpus growth / provenance:** seeds generated from pinned fixtures at
  runtime; any committed corpus file is small and provenance-tracked.

---

## 11. Exit criteria

Milestone 1 is complete when: fuzz targets exist for all six surfaces; the
`fuzz-smoke` CI job runs a bounded campaign on PRs and is green; the nightly
extended workflow is configured; the seeded-defect canary is demonstrably caught
by the harness on Linux CI (and the cross-platform test path runs the targets on
seed corpora everywhere); the existing 11 CI jobs remain green; ruff/mypy clean;
`validate_all()` = 0; no `SECURITY.md` change and no production-code behavior
change; and the "how to run the fuzzers" docs are in place.

---

---

## 12. Amendments incorporated (reviewer, acked)

**Atheris pin (verified against PyPI).** The plan's earlier `atheris>=2.3` was
wrong: `atheris==2.3.0` ships no cp312 wheel (max cp311). Verified Linux wheels:
`3.0.0` → cp311/cp312/cp313; `3.1.0` → cp312/cp313/cp314. **Resolution: pin
`atheris==3.1.0`; run the fuzz job on Python 3.12** (cp312 manylinux2014 x86_64
wheel → ubuntu-latest). The repo floor stays 3.11; the fuzz job uses 3.12 on its
own dedicated job. No floor bump.

**(1) Structural prefix filters (grammar-lite) in the shared target bodies** —
cheap early-returns so the budget isn't burned in the shallow reject path:
`psbt` requires the `psbt\xff` magic; `bech32` requires a non-empty HRP + a `1`
separator; `wif` requires the first char in the WIF set `{5,K,L,9,c}`;
`mnemonic` requires the first token to be in `ENGLISH_WORDLIST`. `transaction`
and `base58` have no cheap structural prefix, so they are seeded instead.

**(2) Fuzz-invocation flags (chosen values, per target):**
`-timeout=5` (per-input seconds; timeouts are findings), `-rss_limit_mb=2048`
(OOM → reported, not silent kill), `-max_len`: PSBT & transaction `65536`;
bech32/base58/wif/mnemonic `1024`. Smoke uses `-max_total_time=30` per target
and a fixed `-seed=1` for reproducibility; nightly drops the fixed seed and
raises `-max_total_time`.

**(3) Determinism.** The six target functions are deterministic (no time,
randomness, or env branching). Note: `keylab.mnemonic.generate_entropy` uses the
CSPRNG and is **deliberately not a target**; the targeted `mnemonic_to_entropy`
/ `is_valid_mnemonic` are pure.

**(4) Fallback naming.** The non-Atheris path is `tests/test_corpus_smoke.py`
(`test_corpus_smoke`), never named `fuzz`; it is **not** counted as fuzz coverage
in CI/report. It calls the **same shared target bodies** (`fuzz/targets.py`) as
the Atheris entry points, so behavior cannot diverge.

**(5) Canary containment (enforced).** `MANIFEST.in` prunes `fuzz/` from the
sdist and src-layout keeps it out of the wheel; a test asserts
`import keylab.fuzz_canary` (and the canary module as a `keylab` submodule)
fails; the canary raises a deterministic `IndexError` on a crafted input (obvious,
not silent). The buggy toy lives only under `fuzz/`, never in `src/keylab/`.

**(Nightly corpus caching).** The nightly job uploads its evolved corpus as a CI
**artifact** and downloads the previous run's artifact to compound coverage.
**Provenance note:** corpus artifacts are *derived* data, not source vectors —
they do **not** go through the `SOURCES.json` gate (that gate governs pinned
official vectors only). PR smoke stays **generated-only, no cache**, so it is
reproducible.

**(7) Numeric exit criteria** (checkable):
- **PR smoke** (`fuzz-smoke`, ubuntu, 3.12): ≤ ~4 min wall (6 targets ×
  `-max_total_time=30` + install/seed), **0 crashes, 0 timeouts**, all six
  targets executed (job log shows each target's libFuzzer banner).
- **Nightly:** `-max_total_time=300` per target, **0 crashes, 0 timeouts**,
  **corpus artifact uploaded**.
- **Canary:** caught in the smoke run (the dedicated canary invocation exits
  non-zero / produces a crash artifact).
- **No regression:** the 8-cell matrix and the existing 11 jobs stay green (CI
  becomes 12 jobs with `fuzz-smoke`).

---

READY FOR FUZZING MILESTONE REVIEW — proceeding to implementation under these
amendments.

---

## 13. Validation record: nightly corpus cache round-trip (resolved)

The nightly corpus cache (restore + evolve + artifact upload) was **round-trip
validated post-merge on 2026-11-04**, via two on-demand `workflow_dispatch` runs
on `main` (`seconds=20`):

- **Run 1 — cold, `41907544746`** (success): cache **miss** on key
  `fuzz-corpus-41907544746` / restore-key `fuzz-corpus-`; artifact `fuzz-corpus`
  uploaded at **163,657 B**; cache saved under `fuzz-corpus-41907544746`.
- **Run 2 — warm, `41908000374`** (success): cache **hit** restoring
  `fuzz-corpus-41907544746` (run 1's corpus, not a rebuild); artifact
  `fuzz-corpus` uploaded at **202,596 B**.
- Corpus **compounded** across runs (163,657 B → 202,596 B); both runs reported
  `fuzz run clean: no crashes or timeouts`.

(Background: before merge, `workflow_dispatch` was unavailable on the branch
because GitHub registers workflows only from the default branch, so the REST
dispatch returned HTTP 404; validation therefore ran immediately after the
fast-forward registered `fuzz-nightly` on `main`.) The **PR smoke path** is
generated-only (no cache) and was validated independently.

**Open follow-up:** the compounding above means the corpus (and its cache) grows
unbounded at the 300s cadence — a size/eviction cap is required before the
nightly runs unattended for weeks. Tracked separately (not milestone-2 scope).
