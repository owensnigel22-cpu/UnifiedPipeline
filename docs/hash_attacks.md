# SHA-256 attacks at reduced/truncated scale (`keylab.research.hash_attacks`)

Two well-known SHA-256 facts, demonstrated at a scale that fits the honest wall.
Neither threatens SHA-256's pre-image or collision resistance; both are teaching
tools. See [../SECURITY.md](../SECURITY.md).

## The wall (read this first)

**A full SHA-256 pre-image is infeasible.** Inverting a 256-bit digest is a
`2**256` search — about `10**77` operations, on the order of **`10**60` years**
at an optimistic `10**12` guesses/sec. No budget, no parallelism, and no amount
of patience changes the exponent. **This is a wall, not a slowdown.** KeyLab
only ever searches a **truncated** digest (the first `bits` bits), where the cost
is an explicit, measured `2**bits`; `bits` is **required** and **hard-capped at
40** — above that `find_truncated_preimage` raises rather than starting an
infeasible search.

## Truncated pre-image (brute force)

`keylab.research.hash_attacks.find_truncated_preimage(target, *, bits, rounds=64,
start=0, max_tries=None, workers=1)` tries counter-encoded messages until one's
SHA-256 (or reduced-round) digest matches `target` in its first `bits` bits. The
expected cost is `2**bits` hashes; every returned message is forward-verified
(its digest's prefix is recomputed and compared). `workers>1` splits the counter
range across stdlib `multiprocessing` processes.

Measured cost (pure-Python `hashlib` loop; see `scripts/benchmark_hash_preimage.py`):

| prefix bits | expected 2^bits | measured tries | wall time | throughput |
|---|---|---|---|---|
| 16 | 65,536 | 58,096 | 0.14 s | ~411k hashes/s |
| 20 | 1,048,576 | 2,491,605 | 7.43 s | ~335k hashes/s |
| 24 | 16,777,216 | 16,175,767 | 48.15 s | ~336k hashes/s |

Measured tries track `2**bits` and throughput is flat (~335k hashes/s), as
expected. Extrapolating to the full digest reproduces the wall: `2**256` guesses
at an optimistic `10**12` guesses/sec ≈ **3.7×10^57 years** (~`10**60`). The
benchmark prints this as a **labelled extrapolation**, never by running it.

### Accelerated backend — evaluated, not shipped

`hashlib.sha256` is already an OpenSSL C implementation, and in a tight search
loop the hash is ~84% of per-iteration time. A drop-in swap to `pycryptodome`
measured **~0.26× (3.8× *slower*)** — its per-call object construction dominates —
so no accelerated backend is added. The only real acceleration would be moving
the whole search loop into native code (a Rust `sha2` kernel via PyO3), which is
out of scope for this educational tool; the pure-Python path is the always-correct
reference any such backend would have to match bit-for-bit.

## Length extension (Merkle-Damgård)

`demonstrate_length_extension(original_digest, known_message, secret_length,
extension)` forges `H(secret || known_message || glue_padding || extension)` given
only `H(secret || known_message)` and the secret's **length** — **not** the
secret. It reuses `keylab.hashes.length_extension.sha256_length_extend`.

This is a **structural** property of Merkle-Damgård constructions, not a break of
the compression function: it needs no search, recovers no secret, and does not
dent SHA-256's security. It forges a digest for an attacker-chosen suffix. The
lesson is concrete: **use HMAC, never `H(secret || message)`** for authentication.

The report's `secret_used` field is always `False`, and the demo is verified by an
**independent** recompute: `hashlib.sha256(secret || forged_message)` equals the
forged digest.

## Resource safety

The benchmark runs every search in a subprocess under a hard memory cap and
wall-clock timeout (`scripts/run_capped.py` — a Windows Job Object / POSIX
`RLIMIT_AS`) plus a `psutil` RAM watchdog that aborts at a threshold. The search
itself holds no large structures, so a breach is a clean kill, never a host crash.

## Out of scope

Full SHA-256 pre-image or collision; real-secret/MAC forgery against a live
service. These are teaching demonstrations only.
