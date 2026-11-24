# KeyLab 0.3.0 — Release Notes

**Release date:** 2026-11-24 · **Version:** 0.3.0 · **Python:** >= 3.11 · **License:** MIT

KeyLab is a modular secp256k1 / Bitcoin **cryptographic research-and-teaching** library. Its core elliptic-curve, signature, encoding, and number-theory layers are readable reference implementations validated against published standards and two independent native backends. It is **not** production wallet or signing software. See [`SECURITY.md`](SECURITY.md) for the authoritative scope and the "Walls."

> **Positioning in one line:** correct, independently validated reference code for study; secret-key operations in adversarial settings should use a reviewed constant-time native library (e.g. libsecp256k1).

---

## Highlights since 0.2.0

- **PSBT (BIP-174) role support** — parser/validator/serializer plus the **Signer**, **Finalizer**, **Extractor**, and **Combiner** roles for P2WPKH and P2SH-P2WPKH inputs, each reproducing the official BIP-174 / BIP-143 worked-example vectors byte-for-byte.
- **BIP-143 witness-v0 sighash** calculator and full **BIP-144** transaction serialization (`serialize_transaction`, the exact inverse of `parse_transaction`).
- **BIP-39 mnemonics** (English word list, checksum-pinned; all 24 official vectors, both directions) — for study, not real funds.
- **BIP-340 Schnorr batch verification** (`schnorr_verify_batch`) as a single multi-scalar multiplication with CSPRNG coefficients (first = 1), returning the same verdict as per-signature verification.
- **Multi-scalar multiplication engine** (`multi_scalar_mult`) with naive, Straus/Shamir, and Pippenger methods; `method="auto"` selects by term count.
- **Frozen reference oracle** (`keylab.ec.reference`) and **differential validator** (`keylab.ec.validation`) backing every optimized path.
- **Performance** — pure-Python `k*P` ≈ 2.1× faster (GLV + interleaved wNAF), `k*G` ≈ 1.8× faster (wider generator comb), batch field inversion (Montgomery's trick); native libsecp256k1 used when installed. Results are unchanged versus the reference in every case.

The full, itemized list is in [`CHANGELOG.md`](CHANGELOG.md) under `[0.3.0] - 2026-11-24`.

---

## Capabilities

### Elliptic-curve cryptography (reference, validated)
secp256k1 domain parameters; affine and Jacobian point arithmetic; `scalar_mult` with selectable backends (`auto`, pure-Python variants, `coincurve`, `fastecdsa`); generator precomputation; wNAF; GLV endomorphism and scalar decomposition (Babai rounding); Straus/Shamir and Pippenger MSM; batch inversion; SEC1 parse/serialize; strict point validation and infinity handling. Every optimized path is differentially checked against the frozen textbook oracle and, where installed, against libsecp256k1 and fastecdsa.

### Signatures (reference, validated)
- **BIP-340 Schnorr** signing and verification (any message length), x-only key lifting with even-`y` parity, and randomized **batch verification**.
- **ECDSA** with **RFC 6979** deterministic nonces and low-`S` normalization.
- Validation: 19 official BIP-340 vectors (9 valid / 10 invalid) matching KeyLab and libsecp256k1; RFC 6979 determinism and ECDSA verify checked against the `ecdsa` package.

### Encoding, wallet, and addresses (reference, validated)
Base58Check, bech32/bech32m, WIF, the `HASH160(pubkey) = RIPEMD160(SHA256(pubkey))` pubkey→address pipeline (P2PKH, P2WPKH, P2SH-P2WPKH), Taproot (BIP-341) outputs, transaction parse/serialize (BIP-144), BIP-32 HD keys, and BIP-39 mnemonics. Input validation is strict (SEC1 length/parity/on-curve, compressed-key witness policy per BIP-143, boolean-scalar rejection).

### Number theory and RSA (research/education)
Extended Euclidean algorithm, modular inverse, totient, modular exponentiation; textbook RSA round-trip; **Wiener** short-exponent *candidate* recovery screened by candidate validation and Miller–Rabin probable-prime tests; bounded Pollard–Brent factoring; shared-factor detection.

### SAT and cryptanalytic research (reduced-round / bounded only)
CNF/ANF construction, a DAG hash model, solver orchestration with timeout handling, and reduced-round SHA-256 / RIPEMD-160 experiments. Every SAT solution is re-verified against the model. Bounded-interval and toy-curve ECDLP demonstrations (kangaroo, rho, BSGS, point-halving, backward double-add) forward-verify every candidate and are never on the signing path.

---

## Milestone 8 benchmark findings (BIP-340 verification paths)

Measured with `scripts/benchmark_msm_schnorr_batch.py` (seed `20261122`, repetitions 5, batch sizes 1–256); artifacts in `benchmarks/milestone8_schnorr_msm.{json,csv}` and `KEYLAB_MILESTONE8_REPORT.md`.

- **Native individual verification (libsecp256k1 via Coincurve) is the fastest path** — ≈ 7–9× faster than pure-Python individual verification at every batch size (median at size 256: native ≈ 14.6 ms vs Python individual ≈ 106.9 ms).
- **Pure-Python randomized batch verification is *slower* than pure-Python individual verification** at every tested size (≈ 1.3–1.7×), with **no crossover**. Parsing and point-lifting dominate the Python cost. The batch path's value is **mathematical independence** (an all-or-nothing single-MSM check), **not** throughput.
- **No native batch API exists** in Coincurve 19.0.1 (no batch verify, no MSM primitive); this is reported as unavailable and is **not** simulated.
- **Differential corpus:** 3,057 native↔Python agreements, 18 malformed inputs classified separately, **0 disagreements**.

> This supersedes any earlier informal claim that Python batch verification is faster than one-by-one verification: the Milestone 8 measurements show it is not.

---

## Validation evidence (this release, verified 2026-11-24)

Environment: Python 3.14.7 on Windows 10; backends `coincurve 19.0.1`, `fastecdsa 4.0.0`, `ecdsa 0.19.2`, `gmpy2 2.3.2`.

| Check | Command | Result |
|---|---|---|
| Full test suite | `python -m pytest` | 2,533 passed, 0 skipped, **9 deselected** (deselected = `slow`/`live` tests excluded by default config, **not** failures) |
| Ruff | `python -m ruff check .` | clean |
| mypy ratchet | `python scripts/mypy_ratchet.py` | 0 errors (baseline 0) |
| CLI self-test | `python -m keylab.cli selftest` | 25/25 PASS |
| Invariant harness | `python scripts/verify_invariants.py` | 25/25 |
| API docs freshness | `python scripts/gen_api_docs.py` | `docs/api.md` already current |
| Whitespace | `git diff --check` | clean |

CI (`.github/workflows/ci.yml`) additionally enforces these across Ubuntu/Windows × Python 3.11–3.14 with zero-skip gates and coverage floors, and requires both native backends.

---

## Installation

```
python -m pip install .                    # core
python -m pip install ".[fast]"            # + libsecp256k1 (coincurve) acceleration
python -m pip install -e ".[dev,all-backends]"   # contributor setup (matches CI, 0 skips)
```

Entry points: `keylab` (CLI) and `keylab-advanced`. Run `keylab --version` to confirm `0.3.0`.

---

## Known limitations (read before use)

- **Not production cryptography.** Pure-Python signer/verifier is a readable reference and is **not constant-time**; no side-channel or timing guarantee is made. Use a reviewed native library for secret-key operations in adversarial settings.
- **Not wallet software for real funds.** Mnemonic generation, PSBT roles, and wallet helpers are for study; broadcasting requires explicit opt-in and is out of scope for safety.
- **RSA components are educational**, not production RSA — no OAEP/PSS padding; Wiener recovery yields *candidates* screened by probable-prime tests (not primality certificates).
- **Reduced-round is not full-round.** Reduced-round / constrained-input SHA-256 and RIPEMD-160 experiments do **not** invert full 64-round SHA-256; no full-round preimage or collision is attempted or claimed. Negative results are recorded, not hidden.
- **No hash inversion or public-key recovery from addresses.** KeyLab does **not** reverse `HASH160`, and does **not** recover a public key from a Bitcoin address or from a hash. `HASH160(pubkey) = RIPEMD160(SHA256(pubkey))` is a one-way forward construction.
- **ECDLP demonstrations are bounded/toy only** and are not practical attacks on secp256k1.

See [`SECURITY.md`](SECURITY.md) and [`docs/SECURITY_POSITIONING.md`](docs/SECURITY_POSITIONING.md) for the complete, authoritative statement of scope.

---

## Compatibility note

KeyLab remains a **0.x development-stage** project: no public-API-stability commitment is made across minor versions. `docs/api.md` marks the surfaces intended to be stable. (A `v1.0.0` Git tag exists in the repository's history but is **not** aligned with this 0.x package-version scheme; it is documented separately for review and does not indicate a 1.0 API commitment.)
