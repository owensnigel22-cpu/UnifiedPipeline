# Benchmarks

Keylab's benchmarks report performance metrics only: timings, throughput,
and correctness flags. They never print scalars, private keys, WIFs, or
signatures, including any secrets loaded from a user-supplied file. The
comparison benchmarks (`benchmark-ec`, `benchmark-signatures`) use a seeded
public corpus, check correctness before timing, exclude warm-up, shuffle
method order per repetition, and report the **median**; see
[Methodology](#methodology) for how inputs are produced for each command.
Throughput depends heavily on the machine; re-measure before citing numbers.

| Command | Measures |
|---|---|
| `keylab benchmark-ec` | Generator multiplication across Python, GLV, wNAF, affine-window, v65 window, and native backends |
| `keylab benchmark-signatures` | BIP-340 sign/verify, ECDSA sign/verify, BIP-32 CKDpriv/CKDpub, Taproot tweak (public and secret) and key-path signing, MuSig2 KeyAgg |
| `keylab benchmark-pubkey` | WIF decoding → public key stages |
| `keylab benchmark-wifs` | Multi-key WIF → address pipelines, per address type |
| `keylab benchmark-hash160` | HASH160 on unique public keys |

`benchmark-signatures` options: `--count`, `--seed`, `--repetitions`,
`--backend {all,keylab,coincurve}`, `--json`. Keylab rows use
`scalar_mult(backend="auto")`, so their point multiplications run on
libsecp256k1 whenever coincurve is installed; the report's
`keylab_multiplication` field records which path was used. To time pure
Python, run in an environment without coincurve.

## Methodology

### Where inputs come from

| Command | Inputs |
|---|---|
| `benchmark-ec`, `benchmark-signatures` | Seeded public corpus from `random.Random(seed)` and hashes of the seed; the seed is in the report |
| `benchmark-pubkey` | One fixed public fixture derived from a constant label |
| `benchmark-hash160` | Deterministic public fixtures derived from a constant label and an index |
| `benchmark-wifs` | Synthetic keys generated at random for each run (not seeded), or, with `--wif-file`, WIFs read from a local file the user supplies |

When `benchmark-wifs --wif-file` is used, the WIFs are read locally and used
only to time the derivation pipeline; they are not printed, returned, or
written anywhere. Use throwaway keys for benchmarking all the same.

### Rules for the comparison benchmarks

`benchmark-ec` and `benchmark-signatures` follow these rules, so their results
are comparable across runs and safe to share:

1. **Seeded, public corpus.** No user-supplied keys are involved, and the
   same seed reproduces the same inputs.
2. **Correctness gate.** Before anything is timed, outputs are checked:
   multiplication backends against the Python reference; BIP-340 signatures
   verified and compared byte-for-byte with libsecp256k1; ECDSA signatures
   verified; CKDpub compared with CKDpriv; tweaked secret keys checked against
   tweaked output keys; MuSig2 KeyAgg compared with an independent
   coefficient-wise sum. A mismatch aborts the run.
3. **Warm-up excluded.** Each method runs once untimed (lazy tables, imports),
   and that time is reported separately.
4. **Shuffled order.** Method order is randomised per repetition (seeded) so
   thermal or cache drift does not favour one method.
5. **Median.** Each repetition times the whole corpus; the median over
   repetitions is reported along with every sample.
6. **Metrics only.** Reports contain timings, throughput, and correctness
   flags; they omit scalars, keys, WIFs, and signatures.

**Interpreting results.** Timings vary with machine load: the two same-day
runs below differ by up to about 2x even for libsecp256k1. Compare rows from
the same run, use `--repetitions` of 5 or more, and re-measure before citing
numbers. `musig2-key-agg` aggregates a sorted group of `MUSIG2_GROUP_SIZE` (3)
keys per operation.

## Recorded results (2026-10-30)

Machine: Windows 10 (10.0.19045), Python 3.14.7, coincurve 19.0.1.
Command: `keylab benchmark-signatures --count 16 --repetitions 5`
(Keylab multiplication: auto → libsecp256k1 via coincurve).

| Operation | Implementation | Run 1 ops/s | Run 2 ops/s | Run 2 µs/op |
|---|---|---:|---:|---:|
| schnorr-sign | keylab | 1,420 | 1,116 | 895.7 |
| schnorr-sign | libsecp256k1 | 7,835 | 7,040 | 142.0 |
| schnorr-verify | keylab | 2,322 | 1,711 | 584.4 |
| schnorr-verify | libsecp256k1 | 17,790 | 13,215 | 75.7 |
| ecdsa-sign | keylab | 6,156 | 3,066 | 326.2 |
| ecdsa-sign | libsecp256k1 | 19,422 | 10,145 | 98.6 |
| ecdsa-verify | keylab | 2,834 | 1,829 | 546.7 |
| ecdsa-verify | libsecp256k1 | 17,553 | 8,227 | 121.6 |
| bip32-ckdpriv | keylab | 4,320 | 4,809 | 208.0 |
| bip32-ckdpub | keylab | 1,798 | 925 | 1,080.8 |
| taproot-tweak-pubkey | keylab | 1,607 | 1,092 | 915.7 |
| taproot-tweak-seckey | keylab | 10,260 | 5,568 | 179.6 |
| taproot-sign | keylab | 1,398 | 663 | 1,507.4 |
| musig2-key-agg | keylab | — | 766 | 1,305.2 |

Run 1 predates the MuSig2 row.

Command: `keylab benchmark-ec --count 12 --repetitions 5`

| Method | keys/s |
|---|---:|
| python | 377 |
| python-affine-window | 1,799 |
| python-glv | 459 |
| python-wnaf | 388 |
| v65-windowed | 1,159 |
| coincurve | 10,372 |

### Observations

- Keylab's BIP-340 signing costs about 3-4× its ECDSA signing. Most of the gap
  is the mandatory self-verification and the affine `point_add_affine`
  (one modular inversion per addition) used in verification.
- Verification (both schemes) does two independent multiplications and an
  affine addition; a joint (Strauss–Shamir) multiplication would remove most
  of that overhead.
- CKDpub is slower than CKDpriv because it adds points in affine form and
  re-validates the parent point on every step.

These are the main targets in the next-release roadmap.
