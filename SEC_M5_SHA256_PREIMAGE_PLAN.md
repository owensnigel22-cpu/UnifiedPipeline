# SEC_M5 — Truncated SHA-256 pre-image + length extension (PLAN)

Status: **PLAN ONLY — no code.** Per the standing rule (plan doc → ack → code →
gates → merge), this scopes the work and waits for ack. Nothing here changes
behaviour. **M6 (Bellcore) is not started.**

**Revised for the lifted project constraints (2026-11-08):** dependencies
(including C/Rust/`pycryptodome` hash backends), network access, and test skips
(`@pytest.mark.slow`, OS-specific `skipif`) are now **permitted**. This plan uses
them where they help (speed, heavy opt-in tests) but keeps every safety rail: the
`bits <= 40` hard cap, the `scripts/run_capped.py` memory/timeout guards plus a
`psutil` RAM watchdog, reduced/truncated scale only, and a pure-Python reference
that any accelerated backend is differentially checked against.

Sequence position: after the M2a/M3/SECURITY/Phase-2/SAT/M4 + RFC-6979/walkback
work merged to `main` (`680be40`). M5 is the next milestone.

---

## 0. Honest framing (the wall, stated up front)

M5 demonstrates two well-known SHA-256 facts at **reduced/truncated scale only**:

- **Full SHA-256 pre-image is infeasible.** Inverting a full 256-bit digest is a
  ``2**256`` search — about ``10**77`` operations, on the order of ``10**60``
  years at ``10**12`` guesses/sec. No budget, no parallelism, and no amount of
  patience changes the exponent. **This is a wall, not a slowdown.** M5 searches
  only a **truncated** digest (the first ``bits`` of the output, ``bits`` a
  required parameter capped at ~40), where the cost is an explicit, measured
  ``2**bits`` and the wall is reached by extrapolation, never by running it.
- **Length extension is a *structural* property of Merkle-Damgård**, not a
  break of the compression function: given ``H(secret || message)`` and the
  length of ``secret || message`` (but **not** the secret), one can compute
  ``H(secret || message || padding || extension)``. It needs no search and
  recovers no secret; it forges a digest for a controlled suffix. The lesson is
  "use HMAC, not ``H(secret || message)``."

Neither result threatens SHA-256's pre-image or collision resistance.

---

## 1. Verify-before-acting: what already exists (do NOT regenerate)

| Capability | Where | Status |
|---|---|---|
| Reduced-round SHA-256 (settable rounds 1..64) | `keylab.hashes.reduced.sha256_reduced`, `_sha_compress(block, state, rounds)` | ✅ exists |
| **Length-extension attack** | `keylab.hashes.length_extension.sha256_length_extend` / `SHA256LengthExtension` | ✅ **already implemented** |
| SHA-256 CNF + secret-prefix models | `keylab.hashes.sha256_cnf` (`SHA256CNFModel`, `SHA256SecretPrefixModel`) | ✅ exists |
| **Resource-safe harness** (hard memory cap + subprocess timeout) | `scripts/run_capped.py` (Job Object / RLIMIT_AS), streaming patterns | ✅ **built in PR #32** |

**Genuinely new (the real M5 work):**
- A **truncated-digest pre-image brute-force** search (absent today).
- A **research-framed `keylab.research.hash_attacks`** package that demonstrates
  both, **reusing** `length_extension` and `run_capped` rather than
  reimplementing them.
- A **resource-safe benchmark** that measures ``2**bits`` cost and extrapolates
  to the wall.

---

## 2. Proposed module layout

```
src/keylab/research/hash_attacks/
  __init__.py                 public entry points (re-exports)
  truncated_preimage.py       brute-force pre-image of a truncated SHA-256 digest
  length_extension_demo.py    research-framed demo that REUSES keylab.hashes.length_extension
```

No new namespaces beyond `keylab.research.hash_attacks`. **Dependencies are now
permitted** (project constraints lifted): the brute-force core and benchmark use
stdlib `hashlib` / `multiprocessing` / `subprocess` by default, and **may** use a
faster hash backend (`pycryptodome`, a `hashlib`-compatible C extension, or a Rust
`sha2` binding via PyO3 / `maturin`) if pure Python is too slow for the 32/40-bit
benchmark. The pure-Python path remains the always-correct reference, and any
accelerated backend is **differentially checked** against it (same digest for the
same input) before it is used.

---

## 3. Part A — truncated SHA-256 pre-image (brute force)

### Signature (proposed)
```python
def find_truncated_preimage(
    target_prefix_bits: int, target: bytes, *,
    bits: int, rounds: int = 64, start: int = 0, max_tries: int | None = None,
    workers: int = 1,
) -> PreimageResult | None: ...
```
- Searches candidate messages (a counter encoded to bytes) for one whose
  SHA-256 (or `sha256_reduced` at `rounds<64`) digest matches `target` in its
  **first `bits` bits**. `bits` is **required** and validated: ``1 <= bits <= 40``
  — above 40 it **raises** (``2**40`` ≈ 10^12 hashes is already minutes; higher is
  the wall) rather than attempting an infeasible search.
- Returns the found message + the number of tries (forward-verified: recompute
  the digest and check the `bits`-bit prefix), or ``None`` within `max_tries`.
- `workers > 1` uses `multiprocessing` (stdlib) to split the counter range; each
  worker checks its stride, first hit wins. Deterministic given `start`.
- **Never** searches a full 256-bit digest; the cap makes that structurally
  impossible.

### Tests (independent reference; heavy cases `@pytest.mark.slow`)
- Fast (always-run): recover a **known** small-bits pre-image: pick a message,
  take the first ``bits`` of its digest as the target, search, and assert the
  found message's digest matches on those bits (independent recompute). `bits` ≈
  16–20 (instant).
- Heavy (**`@pytest.mark.slow`**, opt-in — the zero-skip gate is lifted): a 32-bit
  (and optionally 40-bit) recovery under the subprocess memory/timeout guard,
  skipped by default and run in a dedicated CI job or `-m slow`.
- OS-specific guard tests (SIGTERM on POSIX, Job Object on Windows) use
  platform skips (`@pytest.mark.skipif(sys.platform...)`), now permitted.
- `bits > 40` raises; `bits < 1` raises; non-int raises.
- `workers=2` finds the same class of answer as `workers=1` (both forward-verified).
- Reduced-round (`rounds=32`) path verified against `sha256_reduced`.

---

## 4. Part B — length-extension demonstration (reuse)

### Signature (proposed)
```python
def demonstrate_length_extension(
    original_digest: bytes, original_len: int, extension: bytes,
) -> LengthExtensionReport: ...
```
- Thin research-framed wrapper over `keylab.hashes.length_extension.sha256_length_extend`:
  given ``H(secret || message)`` and ``len(secret || message)``, forge
  ``H(secret || message || glue_padding || extension)`` **without the secret**,
  and return the forged digest + the glue padding + a plain-language report of
  what was and was **not** used (the secret was never needed; no secret recovered).
- **Scope guard in the docstring:** this forges a digest for a chosen suffix; it
  does not recover the secret and does not break SHA-256. Mitigation: HMAC.

### Tests (always-run; independent reference)
- Pick a secret + message, compute ``H(secret||message)``; forge an extension;
  then **independently** compute ``hashlib.sha256(secret || message || glue ||
  extension)`` and assert it equals the forged digest (the attack is correct iff
  the real hash of the reconstructed full input matches).
- Confirms the secret is never passed to the forge function (own-key framing).

---

## 5. Benchmark harness (resource-safe, reusing PR #32 patterns)

`scripts/benchmark_hash_preimage.py`, reusing `scripts/run_capped.py`:
- For `bits` in {16, 20, 24, 28, 32}, run the brute-force search **in a
  subprocess under a hard memory cap + wall-clock timeout** (the same
  `run_capped` guard that protects the host), record tries and wall time, and
  confirm ``tries ≈ 2**bits`` on average.
- Extrapolate the fitted ``~2**bits`` cost to the full 256-bit wall and print the
  ``~10**60`` years statement — **extrapolation clearly labelled, never run**.
- Memory stays flat (the search holds no large structures), so the cap mainly
  bounds the timeout; the pattern is inherited for consistency and safety.

---

## 6. Exit criteria (numbers)
- `find_truncated_preimage(bits=20)` finds a forward-verified 20-bit pre-image in
  ≈ ``2**20`` ≈ 1M hashes (sub-second to seconds); `bits > 40` raises.
- `workers=2` halves wall time on a ≥24-bit search (measured, not assumed).
- Length-extension forge matches an independent full recomputation for several
  (secret, message, extension) triples.
- Benchmark prints the measured ``2**bits`` table + the labelled extrapolation to
  the ``2**256`` / ~10^60-year wall, all runs memory-capped and timed.
- All 12 CI jobs green. Skips are now permitted: heavy (≥32-bit) tests use
  ``@pytest.mark.slow`` and OS-specific guards use platform skips. A faster hash
  backend **may** be added as a dependency (differentially checked vs pure
  Python); network is available if ever needed, though test vectors are generated
  locally and no live network is required.

## 7. Risks
- **Accidental big search**: the `bits <= 40` hard cap (raise) and the benchmark's
  memory/timeout guards prevent a runaway; nothing searches a full digest.
- **multiprocessing on Windows (spawn)**: kept optional and deterministic
  (counter stride by worker index); the fast tests use `workers=1`, and the
  `workers=2` test uses a tiny `bits` so spawn overhead is bounded.
- **Accelerated hash backend**: if a C/Rust/`pycryptodome` backend is added for
  speed, it is gated behind a differential check against pure-Python `hashlib`
  (reject on any digest mismatch) and behind the same `bits <= 40` cap and
  resource guards — speed never bypasses the safety rails.
- **Over-claiming**: docstrings and the report state plainly that length
  extension recovers no secret and the truncated pre-image does not dent full
  SHA-256.

## 8. Out of scope
Full SHA-256 pre-image or collision (the wall); any real-secret/MAC-forgery
against a live service; **M6 (Bellcore / fault attacks) — not started**. Length
extension is **reused**, not reimplemented. (Dependencies, network access, and
test skips are now permitted project-wide and are therefore **no longer** out of
scope; the only hard limits that remain are the `bits <= 40` cap, the resource
guards, and the reduced/truncated-scale boundary.)

---

Awaiting ack before writing M5 code.
