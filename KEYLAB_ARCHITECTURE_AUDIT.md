# KeyLab Architecture Audit

**Date:** 2026-11-16
**Scope:** full `keylab/` package (`src/keylab/`, `tests/`, `docs/`).
**Method:** repository inventory + independent re-verification of the arithmetic
and GLV invariants (see `KEYLAB_MATH_VALIDATION.md`), plus the existing automated
suite. The original audit commit recorded **2,383 passed, 14 skipped, 9
deselected**. The subsequent CLI commit added nine tests; the handover's reported
2,392 passes is consistent with that addition, but its raw test output is not
stored in Git and the count cannot be independently established from history.

## Validation records

Keep the following results distinct; they are from different revisions and
dependency sets:

- **Historical audit record (`e85e5ce`):** 2,383 passed, 14 skipped, 9
  deselected, as recorded when the audit was created. Commit `63c84bc` later
  added nine CLI tests. The handover's 2,392-pass figure is arithmetically
  consistent with those additions, but Git does not contain its raw pytest
  output.
- **Copilot local run (2026-11-16):** 2,406 passed, 9 deselected, no skips,
  using Windows/Python 3.14.7 with the `dev`, `fast`, `secp256k1`, and `ecc-alt`
  extras. The project's default pytest configuration excludes `slow` and
  `live` tests.
- **Earlier local run before native ECC extras:** 2,228 passed, 177 skipped,
  9 deselected, and one failure because `coincurve` was not installed. After
  installing `fast`, the affected broadcast-routing test file passed 6/6; the
  full default suite was then rerun with the native ECC test backends installed.
- **Pre-remediation CI at `63c84bc`:** the Windows/Linux Python 3.11–3.14 test
  matrix, full-extras, fuzz-smoke, and benchmark-smoke jobs passed. The lint job
  stopped at Ruff `EXE001` because `run-keylab.py` had a shebang but was not
  executable in Git; later lint steps did not run in that job. The launcher
  shebang has since been removed because documented use invokes it with Python.
- **Remediation CI at `2f4f1ef` (2026-11-16):** both lint runs, both benchmark
  smoke runs, both fuzz smoke runs, both full-extras runs, and the Linux/Windows
  Python 3.11–3.14 test matrix passed.

## 0. Headline finding (read this first)

The integration directive assumes a pile of loose, versioned scripts
(`keylab_v45.py`, `keylab_v75.py`, `unified_sat_pipeline_formidable-v15.py`,
`real_key_recovery.py`, `derive_from_wif.py`, `btc_cracker.py`). **None of those
files exist** anywhere in the repository (verified by search). The repository is
already a mature, modular, test-covered, documented platform:

- **128 source modules** under `src/keylab/`, **129 `test_*.py` files** under
  `tests/` (current repository inventory).
- A `src/`-layout installable package (`pyproject.toml`), two console entry points
  (`keylab`, `keylab-advanced`), ~24 docs under `docs/`, a README and a SECURITY.md.
- A frozen textbook reference oracle (`ec/reference.py`) plus differential
  validation (`ec/validation.py`) — the exact "compare optimized vs slow reference"
  discipline the directive asks for is already built in and exercised by CI.

**Consequence:** the directive's proposed ground-up restructure (into
`keylab/core/field.py`, `keylab/ecc/affine.py`, …) would be a **destructive rewrite
of 128 working, CI-green modules**. That directly contradicts the directive's own
rules ("do not replace working code with untested code") and KeyLab's operating
principle ("never regenerate completed work"). **Recommended: do not restructure.**
The valuable, non-destructive work is this audit, the math-validation report, an
honest-limitations pass, and targeted gap-filling — not a rewrite.

The only loose artifacts at the repo **root** (outside the package) are:

| Path | State | Recommended action |
|---|---|---|
| `toy_hnp_lattice_demo.py` | **empty (0 bytes)** — superseded by `src/keylab/research/hnp_lattice.py` | delete (needs user OK) |
| `keylab_review_bundle.zip` | 223 KB review archive | move out of repo or `.gitignore` (needs user OK) |

## 1. Subsystem map — directive Part → actual implementation

Status legend: **DONE** (implemented, tested) · **PARTIAL** · **RESEARCH** (clearly
labelled experimental) · **MISSING**.

| Directive part | Implementation (file) | Status | Math validation | Tests |
|---|---|---|---|---|
| 1 secp256k1 core / affine | `ec/secp256k1.py`, `ec/reference.py` | DONE | independent + differential (this audit) | `test_secp256k1*.py`, `test_ec_reference.py` |
| 2 Jacobian arithmetic | `ec/secp256k1.py` (`point_double`, `point_add`, `_point_add_mixed`, `_to_affine`) | DONE | differential vs reference | `test_secp256k1*.py` |
| 3 wNAF | `ec/secp256k1.py` (`wnaf_digits`, configurable window) | DONE | `sum(wNAF(k))==k` ×2000 | `test_secp256k1*.py` |
| 4 GLV endomorphism | `ec/secp256k1.py` (`BETA`,`LAMBDA`, `glv_decompose`, `_scalar_mult_glv*`) | DONE | `BETA³≡1`, `LAMBDA³≡1`, `phi(G)=LAMBDA·G`, `k≡k1+LAMBDA·k2` ×10000 | `test_secp256k1*.py` |
| 5 Shamir / Straus | `ec/secp256k1.py` (`_msm_straus`) | DONE | differential vs sum of scalar mults | `test_secp256k1*.py` |
| 6 SEC1 parsing | `ec/sec1.py` | DONE | parity/length/on-curve rejection | `test_sec1.py` |
| 7 BIP-340 | `ec/schnorr.py`, `hashes/tagged.py` (`lift_x`, tagged hash, strict verify) | DONE | BIP-340 KATs | `test_schnorr.py` |
| 8 ECDSA + RFC6979 | `ec/secp256k1.py`, `ec/rfc6979.py` | DONE | RFC6979 determinism, verify | `test_rfc6979.py`, `test_secp256k1*.py` |
| 9 HMAC / HKDF / BIP-32 | `hashes/mac.py`, `hd.py`, `mnemonic.py` | DONE | RFC5869 / BIP-32 / BIP-39 vectors | `test_hd*.py`, `test_mnemonic*.py`, `test_mac.py` |
| 10–12 SHA-256 / RIPEMD-160 research | `hashes/reduced.py`, `hashes/ripemd_cnf.py`, `hashes/sha256_cnf.py`, `research/sha256_reduced/*`, `research/sha256_prob/*`, `research/sha256_differential/*` | RESEARCH | reduced-round only; negative results recorded | `test_sha256_*.py`, `test_ripemd*.py` |
| 13 SAT / symbolic pipeline | `sat/*` (`cnf.py`, `anf.py`, `backends.py`, `cryptominisat.py`, `parallel.py`, `solver.py`, `dag.py`, `diagnostics.py`) | DONE/RESEARCH | every SAT solution re-verified vs model | `test_sat_*.py`, `test_*_cnf.py` |
| 14 Stage 3/4 (Pass A/B) | `research/sha256_reduced/context_shaping.py`, `register_window.py`, `published.py` | RESEARCH | 17-step verified live; 19/20-step impractical (documented) | `test_sha256_context_shaping.py` |
| 15 Extended Euclid / modinv | `numtheory/core.py` | DONE | `a·x+b·y=gcd`, `a·inv≡1` | `test_numtheory*.py` |
| 16 WIF / Base58Check | `encoding/wif.py`, `encoding/base58.py` | DONE | vectors + checksum | `test_wif.py`, `test_base58.py` |
| 17 HASH160 / address | `encoding/address.py` | DONE | vectors | `test_address*.py` |
| 18 Pollard rho / kangaroo | `research/ecdlp/rho.py`, `kangaroo.py`, `bsgs.py`, `negation_map.py` | RESEARCH | bounded; candidate·G==Q verified | `test_kangaroo*.py`, `test_rho.py`, `test_bsgs.py` |
| 19 Incremental range | `research/weak_rng.py` (`(k+1)G=kG+G`) | RESEARCH | verified; bounded | `test_cli_key_weakness.py`, `test_weak_rng*.py` |
| 20 LSB / point-halving | `research/ecdlp/halving_lsb.py`, `halving_shortcut.py`, `ec/halving.py`, `ec/quartic.py` | RESEARCH | toy-curve + forward-mult checks | `test_halving*.py` |
| 21 Brainwallet / passphrase | `research/brainwallet.py` (binary-streamed wordlist, Bloom multi) | DONE | match re-derived | `test_brainwallet*.py` |
| 22 ECDSA nonce reuse | `research/ecdsa/nonce_reuse.py`, `research/forensics/nonce_scan.py` | DONE | `r1==r2` precondition; recovered key re-verified | `test_forensics_nonce.py`, `test_nonce_reuse.py` |
| 23 Side-channel | `_ct.py`, `crypto_policy.py` | PARTIAL/RESEARCH | constant-time design notes; no fabricated measurements | `test_crypto_policy.py` |
| 24 Self-test | `cli.py` (`selftest` command) | DONE | asserts real checks | `test_cli*.py` |
| 25 Differential testing | `ec/validation.py`, `ec/coincurve_backend.py`, `ec/ecdh.py` | DONE | optional coincurve; skips gracefully | `test_validation.py`, `test_coincurve*.py` |
| 26 CLI | `cli.py` (`keylab`), `advanced_suite.py` (`keylab-advanced`) | DONE | argparse; `parser.error` not tracebacks | `test_cli*.py` |
| 27 No hardcoded targets | CLI takes targets as args; vectors only in tests | DONE | — | — |
| 28 Benchmarking | `benchmarks.py`, `sat/benchmark_throughput.py` | DONE | measured, no invented % | `test_benchmarks*.py` |
| 29 Honest limitations | `SECURITY.md`, `docs/SECURITY_POSITIONING.md` | DONE | the "Walls" | — |
| 30 Cleanup | package already clean; root artifacts flagged above | PARTIAL | — | — |

## 2. Beyond the directive (already present, not requested)

`psbt/*` (BIP-174), `encoding/taproot.py` (BIP-341), `encoding/bech32.py`,
`ec/musig2.py` (BIP-327), `verify/mainnet/*` + `verify/node/*` (read-only chain
verification), `wallet/*` (coin selection, tx build, broadcast adapters),
`research/forensics/*` + `research/weak_rng_milksad.py` (the forensics suite,
Phases A–E merged — the unified `keylab forensics` CLI landed via PR #45).

## 3. Issues found

The audit did **not** find mathematically incorrect core code, placeholder
arithmetic, or unsupported cryptographic claims in the shipped package. Specifics:

- **No incorrect GLV constants.** The directive's stated risk (untrusted
  `BETA`/`LAMBDA`/`A1`/`B1`…) does not materialise: all endomorphism invariants pass
  independent verification (`KEYLAB_MATH_VALIDATION.md`).
- **No "repeated affine add" scalar-mult bug** (the Part-2 trap): the loop updates
  the addend (`point_double`) correctly; 2,000 randomized scalars match the
  from-scratch reference exactly.
- **Research claims are already walled.** SHA-256/RIPEMD-160 inversion, full
  ECDLP, and HASH160→pubkey are explicitly disclaimed in `SECURITY.md`; reduced-round
  and bounded-interval scope is enforced in code and tests. Negative solver results
  (belief-propagation / MILP not inverting SHA-256; 19/20-step search impractical)
  are recorded, not hidden.
- **WIF boolean input follow-up (not changed in this remediation):**
  `keylab.encoding.wif.encode(True)` currently accepts `True` as integer scalar 1
  and emits its valid WIF. This is inconsistent with strict scalar validation in
  other KeyLab APIs, and `tests/test_wif.py` has no boolean-input regression test.
  Rejecting booleans and adding a focused test is recommended as a separate,
  narrowly scoped change; this behavior is not a break in WIF or secp256k1.
- **Minor, non-code:** two loose root artifacts (table in §0); an empty
  `toy_hnp_lattice_demo.py` duplicating `research/hnp_lattice.py`.

## 4. Recommended actions (for user decision — no major merge performed)

1. **Do not restructure** the package into the directive's `core/ecc/...` tree;
   it is a destructive rewrite of working code with no correctness upside.
2. **Housekeeping (needs explicit OK, touches files):** delete the empty
   `toy_hnp_lattice_demo.py`; move/ignore `keylab_review_bundle.zip`.
3. **Optional additions (additive) — DELIVERED in this branch:** a `run-keylab.py`
   launcher mapping to `keylab.cli:main` (named `run-keylab.py`, not `keylab.py`,
   which would shadow the package and break every import); a `keylab interactive`
   numbered-menu mode wrapping the existing subcommands; and an expanded `selftest`
   asserting the full invariant list.
4. PR #45 (unified `forensics` CLI) is merged.

See `KEYLAB_MATH_VALIDATION.md` for the invariant evidence table.
