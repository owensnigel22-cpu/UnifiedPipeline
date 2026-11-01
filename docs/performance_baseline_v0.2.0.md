# Performance baseline: KeyLab v0.2.0

Reference measurements of the released v0.2.0 code (`v0.2.0` = `e995a41`), taken
before any M2 arithmetic work so that 0.3.0 speed-ups are measured against a
fixed point. Raw reports are in [`baselines/v0.2.0/`](baselines/v0.2.0/).

**Read these as relative numbers.** They come from one desktop machine; absolute
timings differ between machines and between runs (see *Variance*). Compare a
later run with this one only on the same machine, or compare ratios.

## Environment and method

- Machine: Windows-10-10.0.19045-SP0, AMD64; Python 3.14.7.
- Code: a clean export of the `v0.2.0` tag, installed into two fresh virtual environments:
  - **pure**: no native backend, so every multiplication is KeyLab's Python code;
  - **native**: coincurve 19.0.1 installed, so `backend="auto"` multiplications use libsecp256k1.
- Micro-benchmarks: `scripts/bench_micro.py` (seed 20261031), 5 repetitions per
  metric, median; the whole script run 3 times per environment and the per-metric
  median of the runs reported. Every run is kept in the JSON (`per_run_results_us`).
- Operation benchmark: `keylab benchmark-signatures --count 16 --repetitions 5 --json`
  (correctness-gated, seeded corpus, median of repetitions).
- Generator benchmark: `keylab benchmark-ec --count 12 --repetitions 5`.

## Field and point primitives (pure Python)

| Primitive | µs |
|---|---:|
| Jacobian doubling | 5.6 |
| Jacobian addition | 9.5 |
| Mixed Jacobian + affine addition | 8.3 |
| Field inversion `pow(x, -1, P)` | 34.1 |
| Square root mod p (`sqrt_mod_p`) | 189.2 |

## Scalar multiplication strategies (pure Python)

| Strategy | ms |
|---|---:|
| k·G, `python` (double-and-add) | 2.38 |
| k·G, `python-wnaf` | 2.20 |
| k·G, `python-affine-window` (the `auto` path without a native backend) | 0.55 |
| k·P, `python` (double-and-add; the `auto` path for arbitrary points) | 3.25 |
| k·P, `python-glv` (bitwise GLV, no windows) | 2.06 |

## Public operations: pure Python vs native multiplication

| Operation | Pure Python (ms) | With coincurve (ms) | Ratio |
|---|---:|---:|---:|
| ECDSA verify | 6.01 | 0.24 | 25× |
| BIP-340 verify | 5.80 | 0.41 | 14× |
| BIP-340 sign (includes self-verification) | 9.24 | 0.63 | 15× |
| Taproot output tweak | 1.86 | 0.43 | 4× |

## `benchmark-signatures` (µs per operation, median)

| Operation | KeyLab, pure Python | KeyLab, `auto` → libsecp256k1 | libsecp256k1 (coincurve) |
|---|---:|---:|---:|
| `schnorr-sign` | 8,800 | 651 | 129 |
| `schnorr-verify` | 5,934 | 435 | 90 |
| `ecdsa-sign` | 1,575 | 217 | 63 |
| `ecdsa-verify` | 5,682 | 242 | 57 |
| `bip32-ckdpriv` | 3,020 | 208 | — |
| `bip32-ckdpub` | 2,026 | 561 | — |
| `taproot-tweak-pubkey` | 2,015 | 450 | — |
| `taproot-tweak-seckey` | 1,506 | 97 | — |
| `taproot-sign` | 10,231 | 700 | — |
| `musig2-key-agg` | 9,880 | 905 | — |

## Variance

Across the three micro-benchmark runs in the pure environment, the slowest run
was at most 1.77× the fastest for `taproot_output`, 1.34× the fastest for `mixed_add`, 1.28× the fastest for `schnorr_verify`;
all other metrics varied by less than 1.25×. A single earlier run measured BIP-340
verification at 9.6 ms, against the 5.8 ms median here, which is why every number
above is a median of medians. Treat differences under about 1.3× as noise.

## Findings that set the M2 targets

- **Backend discovery dominates pure-Python verification.** A profile of 20 ECDSA
  verifications (pure environment) spent 58 of 137 ms, about 42%, in
  `importlib.util.find_spec`: `scalar_mult(backend="auto")` looks for coincurve
  and fastecdsa on disk on every call (two probes per multiplication, each a
  series of filesystem `stat` calls). This is why verification (6.0 ms) costs far
  more than its two multiplications (0.55 + 3.25 ms). Caching the discovery is
  the first M2 item; it changes no arithmetic.
- **k·G is already windowed.** `python-affine-window` costs 0.55 ms once its table
  exists (the table build is a one-off cost). A larger fixed-base comb saves at
  most about 1.8×, not the 4× estimated during planning, when the measurement used
  included the table build.

## What M2 must show against this baseline

Measured in the pure environment on this machine with the same scripts
(revised from the planning estimates using the findings above):

- ECDSA and BIP-340 verification at least 2.5× faster (from 6.01 and 5.80 ms);
- k·P at least 2× faster than `python` (from 3.25 ms);
- k·G at least 1.7× faster than `python-affine-window` (from 0.55 ms);
- no regression in the native environment, where `auto` must keep using libsecp256k1.

## Progress against this baseline

### M2.0: backend discovery cached (no arithmetic change)

`benchmark-signatures --count 16 --repetitions 5`, same machine, before (`a41edf9`)
and after the change, µs per operation:

| Operation | Pure Python before | Pure Python after | Speed-up |
|---|---:|---:|---:|
| `schnorr-sign` | 9,673 | 4,916 | 1.97× |
| `schnorr-verify` | 7,400 | 3,974 | 1.86× |
| `ecdsa-sign` | 1,942 | 588 | 3.31× |
| `ecdsa-verify` | 6,332 | 3,979 | 1.59× |
| `bip32-ckdpriv` | 3,808 | 1,097 | 3.47× |
| `bip32-ckdpub` | 2,111 | 1,020 | 2.07× |
| `taproot-tweak-pubkey` | 1,998 | 921 | 2.17× |
| `taproot-tweak-seckey` | 1,587 | 595 | 2.67× |
| `taproot-sign` | 11,772 | 5,540 | 2.12× |
| `musig2-key-agg` | 10,553 | 7,270 | 1.45× |

Micro-benchmarks (median of 3 runs) agree: ECDSA verify 6.39 → 3.76 ms (1.70×),
BIP-340 verify 6.03 → 4.03 ms (1.50×), the multiplications themselves unchanged
(k·G 0.56 → 0.55 ms, k·P 3.33 → 3.34 ms). With coincurve installed, an
interleaved A/B run (three alternating runs of each version) found no
regression: the new median was at or below the old one for every operation.

### M2.2: batch normalization (shared primitive; no change to existing operation paths)

`batch_to_affine` vs per-point `_to_affine` on Jacobian points with random Z
(pure Python, median of 7):

| Batch size | Per point, one at a time | Per point, batched | Speed-up |
|---:|---:|---:|---:|
| 1 | 31.0 µs | 36.0 µs | 0.9× |
| 2 | 33.0 µs | 21.0 µs | 1.6× |
| 8 | 32.5 µs | 9.9 µs | 3.3× |
| 64 | 35.6 µs | 8.2 µs | 4.4× |
| 960 | 36.5 µs | 6.0 µs | 6.1× |

Generator affine-window table build (one-off per process): 29.3 → 20.1 ms;
the table is identical. Verification, signing, BIP-32, Taproot, and MuSig2
timings are unchanged (0.93–1.13×, within noise), as expected: each of those
paths normalizes one point at a time today. The batch primitive pays off in the
later M2 steps (precomputed tables, multi-scalar multiplication, batch
verification). In the native environment, a balanced ABBA run found no
regression (Taproot output 1.10×, BIP-340 sign 1.02×, k·G 1.00×). An earlier
run in which the new code always ran second showed a spurious 0.6× from that
ordering.

### M2.4: generator-table optimization (fixed-base comb, 4-bit -> 8-bit window)

k*G uses a fixed-base comb; widening its window from 4 to 8 bits halves the
per-call additions (64 -> 32). Pure Python, same machine:

| Metric | 4-bit (v0.2.0) | 8-bit (M2.4) | Change |
|---|---:|---:|---:|
| Warm k*G | 589 us | 325 us | **1.81x faster** |
| Table build (one-off, lazy, cached) | 19.8 ms | 159 ms | +139 ms |
| Table size | 185 KB (960 pts) | 1.5 MB (8160 pts) | +1.35 MB |
| Cold first call (fresh process, incl. build) | 46 ms | 198 ms | +152 ms |

Downstream `benchmark-signatures`, pure Python, v0.2.0 vs M2.4 (cumulative with
M2.0's discovery-cache win; k*G-heavy operations gain most):

| Operation | v0.2.0 us | M2.4 us | Speed-up |
|---|---:|---:|---:|
| ecdsa-sign | 1,530 | 374 | 4.09x |
| bip32-ckdpriv | 3,105 | 740 | 4.20x |
| taproot-tweak-seckey | 1,482 | 328 | 4.52x |
| taproot-sign | 10,917 | 5,121 | 2.13x |
| schnorr-sign | 8,943 | 4,432 | 2.02x |
| schnorr-verify | 5,738 | 3,710 | 1.55x |
| ecdsa-verify | 5,798 | 3,819 | 1.52x |
| musig2-key-agg | 10,158 | 7,321 | 1.39x |

Verification gains less because only one of its two multiplications is k*G (the
other is k*P on an arbitrary point, which GLV+wNAF will address next). Results
are bit-identical to the reference: `validate_all()` reports 0 mismatches and
the comb table is the same points at both widths, just laid out in wider
windows. Still a plain unsigned comb -- no signed-digit recoding, no GLV.

### M2.5: GLV + wNAF for arbitrary-point k*P

`k*P` (arbitrary point) was plain double-and-add. It now uses the GLV
endomorphism to split k into two ~128-bit signed halves and evaluates both as
width-4 interleaved wNAF, sharing ~128 doublings and one modular inversion for
the odd-multiple tables. Pure Python, same machine:

| k*P method | us per k*P | vs plain |
|---|---:|---:|
| `python` (plain double-and-add) | 3227 | 1.00x |
| `python-glv` (bitwise GLV, pre-existing) | 2048 | 1.58x |
| `python-optimized` (GLV + wNAF, M2.5) | 1523 | **2.12x** |

Downstream `benchmark-signatures`, pure Python, v0.2.0 -> M2.5 (cumulative with
M2.0 + M2.4; verification now gains because its k*P half is optimized):

| Operation | v0.2.0 us | M2.5 us | Speed-up |
|---|---:|---:|---:|
| bip32-ckdpriv | 3,105 | 629 | 4.93x |
| taproot-tweak-seckey | 1,482 | 309 | 4.79x |
| ecdsa-sign | 1,530 | 372 | 4.11x |
| taproot-sign | 10,917 | 3,032 | 3.60x |
| schnorr-sign | 8,943 | 2,711 | 3.30x |
| ecdsa-verify | 5,798 | 1,849 | 3.14x |
| schnorr-verify | 5,738 | 1,960 | 2.93x |
| taproot-tweak-pubkey | 1,802 | 654 | 2.76x |
| bip32-ckdpub | 2,083 | 769 | 2.71x |
| musig2-key-agg | 10,158 | 3,827 | 2.65x |

Results are bit-identical to the reference (`validate_all()` 0 mismatches; the
GLV+wNAF path equals keylab.ec.reference and both native backends over edge and
random scalars). With a native backend installed, k*P runs on libsecp256k1 and
is unchanged: a balanced ABBA native run gave 1.01x (schnorr-verify) and 1.10x
(k*P auto), within noise. `python` and `python-glv` remain selectable unchanged.

### M2.6: multi-scalar multiplication foundation

`multi_scalar_mult(pairs, method="auto")` returns `sum(k_i * P_i)`. The
foundation (`method="naive"`) sums one optimized per-point `k*P` per term and is
linear in the number of terms; terms are summed streaming, so memory is flat.
Pure Python:

| n | total ms | us/term | peak KB |
|---:|---:|---:|---:|
| 1 | 1.73 | 1732 | 6.3 |
| 2 | 3.00 | 1499 | 6.6 |
| 8 | 13.3 | 1662 | 7.3 |
| 32 | 49.0 | 1531 | 7.4 |
| 128 | 197 | 1542 | 7.5 |

us/term stays ~1500-1700 (one GLV+wNAF `k*P`), so there is **no crossover yet**:
the foundation is the linear baseline. Straus/Shamir (M2.7) shares one doubling
chain across terms to cut us/term for `n >= 2`; Pippenger (later) uses buckets to
win for large `n`. Both will be measured against this table, and their crossovers
documented, when they land. Results are bit-identical to
`keylab.ec.reference.multi_scalar_mult` (`validate_all()` 0 mismatches).

## Reproducing

```bash
git worktree add ../keylab-v0.2.0 v0.2.0
python -m venv pure && pure/bin/pip install -e ../keylab-v0.2.0
python -m venv native && native/bin/pip install -e "../keylab-v0.2.0[secp256k1]"
pure/bin/python scripts/bench_micro.py > micro-pure.json      # run from this checkout
pure/bin/keylab benchmark-signatures --count 16 --repetitions 5 --json
```
