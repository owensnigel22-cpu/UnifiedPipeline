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

## Reproducing

```bash
git worktree add ../keylab-v0.2.0 v0.2.0
python -m venv pure && pure/bin/pip install -e ../keylab-v0.2.0
python -m venv native && native/bin/pip install -e "../keylab-v0.2.0[secp256k1]"
pure/bin/python scripts/bench_micro.py > micro-pure.json      # run from this checkout
pure/bin/keylab benchmark-signatures --count 16 --repetitions 5 --json
```
