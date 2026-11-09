# M10 Optimization, ECDH, and Native Bindings — Plan

**Status:** Acknowledged; implementation in progress.  
**Plan baseline:** `origin/main` at `e9b9850a829422782573832b3fee7cf16aaf7874` (2026-11-09).  
**M10 plan worktree:** `UnifiedPipeline-M10`, branch `docs/m10-optimization-ecdh-plan`.  
**Scope:** Add a first-class ECDH API, explicit libsecp256k1-backed ECDSA/ECDH operations, benchmark them, and evaluate safe batch verification in the existing read-only verification flow.

## 1. Verified baseline and constraints

The canonical `origin/main` was fetched before writing this plan. Its history contains M7 (`0e6abee`, read-only mainnet verification) and the three M9 cryptanalysis commits. The current plan branch starts at the merged tip `e9b9850`; the earlier M9 feature commits are ancestors of that tip.

The repository already has optional `coincurve` support for point multiplication. `pyproject.toml` declares `coincurve>=19.0.1,<20.0` in the `secp256k1`, `performance`, and `all-backends` extras. Existing differential tests compare multiple pure-Python arithmetic implementations to libsecp256k1 when installed. Therefore M10 should add missing operation-level wrappers and a convenient `[fast]` extra without introducing a second native implementation or changing existing defaults.

There is no `fast_mul` symbol in `src/` or `tests/`. The corresponding reference operation is `keylab.ec.reference.scalar_mult`; the public optimized facade is `keylab.ec.secp256k1.scalar_mult`. This plan uses those actual interfaces.

## 2. Existing architecture relevant to M10

### ECC and native backend

- `src/keylab/ec/secp256k1.py` provides affine point validation, `scalar_mult`, ECDSA signing/verification, and MSM methods. `scalar_mult(..., backend=...)` already dispatches to Coincurve and preserves explicit backend selection.
- `src/keylab/ec/reference.py` contains the frozen, readable affine `scalar_mult` oracle.
- `src/keylab/ec/validation.py` and `tests/test_ecc_differential.py` establish the independent-backend differential-testing convention.
- `ecdsa_sign_digest` uses the Python RFC 6979 and signature arithmetic. Its `backend` argument selects point multiplication; it does not make the entire signing operation native or constant-time. `ecdsa_verify_digest` currently has no backend selector and performs signature arithmetic in Python.
- `src/keylab/ec/schnorr.py` already implements randomized BIP-340 batch verification using `secrets` coefficients and `multi_scalar_mult`; this is a useful architectural example, but its equations do not directly solve standard ECDSA batching.

### Mainnet verification

- `src/keylab/verify/mainnet/verification.py` validates P2WPKH and P2SH-P2WPKH witness inputs and calls `ecdsa_verify_digest` once per input. `verify_transaction_signatures` checks every input in one supplied transaction.
- `src/keylab/verify/mainnet/client.py` is a GET-only, TLS-validated explorer client. It fetches individual transactions, block headers, and Merkle proofs; it does not fetch or enumerate all transactions in a block.
- M10 can add a collection-level verification API for transactions and caller-supplied spent outputs. Full block download/decoding is outside the current client contract and must not be implied by that API.

### CI, tests, and coordination documents

- `.github/workflows/ci.yml` already has native-backend and full-extras jobs; the latter installs `all-backends`, which includes Coincurve. New native differential tests should run in a required Coincurve-present CI job and must not silently skip there.
- Relevant existing tests include `tests/test_ecc_differential.py`, `tests/test_mainnet_verification.py`, `tests/test_verify_client.py`, `tests/test_verify_mainnet_cli.py`, and `tests/test_verify_mainnet_live.py`.
- `docs/coordination/PROJECT_STATUS.md` and `CURRENT_TASKS.md` are dated snapshots that still describe the earlier `9fc9760` state. After approval, update them with the verified M10 baseline and task ownership; do not edit them during this planning-only step.

## 3. Proposed API and implementation design

### 3.1 First-class ECDH

Add `src/keylab/ec/ecdh.py` with a stable public operation and a named reference implementation:

```python
ecdh(privkey: int, pubkey: Point | bytes, *, backend: str = "auto") -> bytes
ecdh_reference(privkey: int, pubkey: Point | bytes) -> bytes
```

The API will validate `1 <= privkey < N`, require a valid finite secp256k1 public point, accept either a validated affine point or SEC1-encoded public key, and return the 32-byte big-endian x-coordinate of the shared point. The reference path will call `reference.scalar_mult`; it will not call the optimized facade, preserving oracle independence. The native path will use Coincurve/libsecp256k1 point multiplication and extract the x-coordinate from compressed point serialization.

**ECDH output compatibility is a decision gate.** Coincurve's documented `PrivateKey.ecdh` returns a hash of the compressed shared point by default, not the raw x-coordinate requested here. The wrapper must not return that hash under an x-coordinate API. The exact pinned Coincurve 19 API must be checked before implementation; if it cannot expose the raw x-coordinate safely through its supported public interface, M10 must either implement an explicit native point-multiplication path or revise the API with owner approval. The raw x-coordinate is key material, not a finished application key: callers should derive context-separated keys with a KDF.

The default `auto` backend uses Coincurve when available and falls back to the pure-Python reference when it is not installed, as requested for this milestone. Callers can explicitly select `python` or `coincurve`; an explicit native request with the optional dependency missing must raise an actionable install error. The API documentation must state that the Python fallback is variable-time and is not suitable for protecting production secrets.

### 3.2 Coincurve ECDSA wrappers

Add an isolated adapter, proposed as `src/keylab/ec/coincurve_backend.py`, with explicit native functions for digest-based ECDSA sign and verify. Do not redefine the existing `backend` argument on `ecdsa_sign_digest`: that argument currently controls only scalar multiplication, so expanding its meaning could change callers' security assumptions.

- Native signing will pass the already-computed 32-byte digest with Coincurve hashing disabled, parse its strict DER output into the existing `(r, s)` tuple, and retain libsecp256k1's deterministic nonce and low-S behavior.
- Native verification will validate the same digest, point, and scalar ranges as the pure-Python API, serialize the signature to DER, and call Coincurve with hashing disabled. High-S behavior must be made explicit: if libsecp256k1 rejects high-S signatures while KeyLab accepts mathematically valid high-S signatures, normalize `s` to `N-s` only in the adapter and test equivalence. Never quietly narrow the existing pure-Python verifier's accepted set.
- Explicit backend requests must never fall through to a different backend. The Python reference remains the differential oracle.

### 3.3 ECDSA batch verification and M7 integration

Coincurve exposes single-signature ECDSA verification, not a public batch-verification operation. KeyLab already has optimized MSM implementations, but a direct randomized MSM of ordinary ECDSA equations is **not** sufficient: an ECDSA signature carries `r = x(R) mod N`, not the nonce point's y-coordinate (and `x` may be `r` or `r+N`). A correct batch algorithm must handle that ambiguity and include sound randomization; simply aggregating the existing `(uG + vQ)` calculations would be incorrect.

Before implementation, perform a focused algorithm review against published standard-ECDSA batch-verification work (see References). Select and document a concrete algorithm, its assumptions, randomizer entropy, and false-accept bound. If no reviewed algorithm maps cleanly to KeyLab's secp256k1/MSM interface, do not ship ECDSA batching in M10; use native per-signature verification and record the batch path as a no-go.

If that gate passes:

1. Add an explicit collection API in `src/keylab/verify/mainnet/verification.py` for multiple transactions plus independently supplied spent outputs.
2. Reuse the existing parser, witness checks, sighash construction, SEC1 validation, and `multi_scalar_mult`; do not duplicate transaction validation.
3. Keep `verify_p2wpkh_input` and `verify_transaction_signatures` as deterministic reference APIs. Make probabilistic batch acceptance explicit in a separately named API with a documented soundness bound and cryptographically random coefficients.
4. Add adversarial tests for malformed witnesses, wrong UTXO keys, high-S policy, invalid/canceling batch elements, and exact agreement with individual verification on deterministic test corpora. Test failure localization or a documented deterministic fallback when a batch fails.
5. Do not describe the current explorer client as a block verifier. The collection API can batch caller-provided block transactions, but block transaction retrieval is a separate capability and is not included unless separately approved.

Expected trade-off: batching may reduce point-multiplication work for large batches, but there is setup overhead, probabilistic soundness, and ECDSA nonce-point ambiguity. Benchmark batch sizes from 1 upward and retain individual verification as the baseline. No performance gain is assumed.

## 4. Differential and regression testing

Add `tests/test_ecdh.py` and extend `tests/test_ecc_differential.py` with deterministic cases covering:

- A pinned known secp256k1 ECDH vector, checked against both the pure reference and Coincurve.
- Multiple deterministic private/public key pairs, both SEC1 encodings, and leading-zero x-coordinate handling.
- Invalid scalar boundaries (`0`, `N`, negative, wrong type), infinity, malformed encodings, and off-curve points.
- Native ECDSA signing compared with the Python reference for fixed digests/keys; native-produced signatures verified by both paths and vice versa.
- Valid, high-S-equivalent, out-of-range, malformed DER, wrong-digest, and wrong-public-key ECDSA verification cases.
- Native-unavailable behavior and explicit-backend no-fallback behavior.

If the ECDSA batch research gate passes, add `tests/test_mainnet_verification_batch.py` for the batch-versus-individual matrix. Required CI must install `[fast]` and run native differential tests without skips. Existing minimal-install jobs should continue to test clear optional-dependency errors.

## 5. Benchmark plan

Add `scripts/benchmark_ecc.py`. Use fixed deterministic keys, digests, signatures, and public points; validate each corpus item before timing. Report Python version, OS/platform, Coincurve/libsecp versions, backend availability, warm-up policy, repetitions, medians, minimum/maximum or interquartile spread, and operation counts.

Measure separately:

- Pure-reference and native ECDH.
- Pure and native ECDSA signing.
- Pure and native single ECDSA verification.
- Individual versus batch mainnet verification for batch sizes 1, 2, 4, 8, 16, 32, and larger where practical (only if the batch algorithm passes review).
- End-to-end parsing/sighash/verification as a separate row from primitive-only timings.

Input preparation, digest construction, DER conversion, parsing, and table/precomputation must be stated as included or excluded per measurement. Report raw timings and speed ratios only from actual runs; do not hard-code expected speedups or turn benchmark thresholds into flaky tests.

## 6. Dependency and portability policy

- Add a `[fast]` extra containing the existing tested Coincurve range `coincurve>=19.0.1,<20.0` and retain `[secp256k1]` for backward compatibility. Do not add Coincurve as a mandatory runtime dependency.
- Justification: optional native libsecp256k1 improves secret-scalar operations and verification throughput without imposing native installation on pure-Python users. The project already has this dependency and native backend CI.
- Extend `.github/workflows/ci.yml` so at least one required job installs `[dev,fast]` and executes ECDH/ECDSA differential tests. Preserve an installation path without `[fast]` to validate optional behavior.
- Test the pinned supported Coincurve range on the existing Python/OS CI matrix; do not depend on private Coincurve internals or platform-specific assembly assumptions.

## 7. Security and correctness gates

- Pure-Python ECDH and ECDSA remain variable-time and must be documented as research/reference implementations, not production secret handling.
- Native libsecp256k1 reduces timing risk for supported operations but does not make KeyLab, its parsing, protocol state, or caller workflows audited or production-ready.
- Do not use Coincurve's default hashed ECDH output where the API promises raw x, and do not return the shared point or secret in logs/benchmark output.
- Batch verification uses random coefficients and is probabilistic. Specify the false-accept bound; use `secrets`/CSPRNG only; never use fixed test coefficients in production. Keep deterministic individual verification available.
- Differential tests must compare mathematical outputs and edge-case acceptance semantics, not only normal valid vectors.
- ECDH, signing, and verification require fixed test vectors and independent reference comparisons before any optimized backend becomes the default.

## 8. Proposed post-acknowledgment implementation commits

All commits will be local on a new `experiment/m10-optimization-ecdh` branch based on the then-current verified `origin/main`; no push or merge occurs without a separate explicit instruction.

1. `feat(ec): add reference secp256k1 ECDH` — ECDH API, pure reference path, known vector and edge tests.
2. `feat(ec): add Coincurve ECDH and ECDSA adapters` — native wrappers, `[fast]` extra, differential tests, required CI coverage.
3. `feat(verify): add reviewed ECDSA batch verification` — only if the mathematical review gate passes; otherwise record a no-go and retain individual native verification.
4. `perf(ec): add reproducible ECDH and signature benchmarks` — benchmark script and documented environment/output schema.
5. `docs: record M10 implementation status` — coordination status/task ownership and any security/performance findings.

Each commit receives focused tests and `ruff`/mypy checks; the complete relevant and repository test suites run before handoff. CI must include Coincurve-present and Coincurve-absent paths.

## 9. Decision requested

Approve or revise this plan before implementation. In particular, confirm:

1. The ECDH API returns the raw x-coordinate and uses Coincurve automatically when installed, with a pure-Python fallback for optional-dependency environments.
2. M10 may make ECDSA batch verification an explicit probabilistic API and may declare it a no-go if the algorithm/performance review does not justify integration.
3. M7 remains a read-only signature-verification feature; M10 will not expand the explorer client into a full block downloader.

## References

- Coincurve API (documents that `PrivateKey.ecdh` returns a hash of the compressed shared point by default): <https://ofek.dev/coincurve/api/>
- Bitcoin Core libsecp256k1 (native secp256k1 primitive scope and security notes): <https://github.com/bitcoin-core/secp256k1>
- Karati, Das, Roychoudhury, *Randomized Batch Verification of Standard ECDSA Signatures*, SPACE 2014: <https://cse.iitkgp.ac.in/~abhij/publications/ECDSA-RBV-SPACE2014.pdf>
