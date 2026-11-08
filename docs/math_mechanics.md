# Math mechanics — double-and-add and the walkback trace

Two closely related mechanisms underpin much of KeyLab's EC code and its
teaching tools: the forward scalar multiplication `k·G` (double-and-add) and its
reversal (the *walkback trace*). This note explains both and draws the line
between KeyLab's **mathematical** walkback and a **side-channel execution trace**,
which are often confused.

## Russian multiplication (double-and-add): computing `R = k·G`

Elliptic-curve scalar multiplication computes `R = k·G` — adding the base point
`G` to itself `k` times — but never by `k` additions. Instead it uses
**double-and-add** (a.k.a. "Russian peasant multiplication" applied to a group),
which runs in a number of steps proportional to the **bit length** of `k`, not
its magnitude: about **256 steps** for a 256-bit scalar, versus `~2^256`
additions for the naive method.

Processing the bits of `k` from most significant to least:

```
R = O                      # the identity (point at infinity)
for bit in bits_of_k (MSB → LSB):
    R = 2·R                # DOUBLE
    if bit == 1:
        R = R + G          # ADD
return R                    # R = k·G
```

Each `k`-bit costs one doubling and, when the bit is set, one addition. A 256-bit
scalar therefore needs ~256 doublings and ~128 additions on average — a handful
of microseconds in C, and the reason ECC is practical. KeyLab implements this in
`keylab.ec.secp256k1.scalar_mult`; the windowed/wNAF variants trade precomputation
for fewer additions but follow the same shape.

**Security note.** A *naive* double-and-add branches on secret bits (the `if bit`),
which leaks the scalar through timing and power. Production libraries
(`bitcoin-core/secp256k1`) use constant-time ladders; KeyLab does **not**, and is
unsuitable for secret keys (see [../SECURITY.md](../SECURITY.md)).

## The walkback trace: reversing double-and-add to recover `k`

The *walkback* runs the ladder **backwards**. Given a public key `Q = k·G`, each
forward step was either a double (bit 0) or a double-then-add (bit 1). Reversing
one step means **halving** the point — on secp256k1's odd prime-order group the
unique `P` with `2P = Q` is `((N+1)/2)·Q`, which is exact — and choosing which
predecessor produced `Q`:

- **branch 0**: `Q` came from a doubling → predecessor is `halve(Q)`;
- **branch 1**: `Q` came from `2P + G` → predecessor is `halve(Q − G)`.

Both predecessors are valid curve points, indistinguishable by structure, so the
walkback must **explore both branches** at every step — a binary tree of depth
`bit_length(k)`. The path that reaches the identity `O` spells out the bits of
`k` (LSB-first in KeyLab's accumulation). This is implemented in
`keylab.research.ecdlp.backward_double_add.backward_traverse_to_identity`, and
`scripts/walkback_trace.py` prints the step-by-step path (branch, x-coordinate,
accumulated bits, recovered `k`).

**This is exactly the ECDLP and costs `2^bit_length(k)`** — it has no advantage
over brute force and resolves only small, bounded scalars. It does not threaten a
256-bit key; see the honest wall in
[research/ecdlp_benchmark.md](research/ecdlp_benchmark.md).

## Walkback trace ≠ side-channel execution trace

These share the word "trace" but are fundamentally different:

| | **Mathematical walkback (KeyLab)** | **Side-channel execution trace** |
|---|---|---|
| Input | Only the public key `Q = k·G` | Physical measurements of a device *while it computes* `k·G` |
| Mechanism | Reverse the group operation (halving + branch search) | Observe timing / power / EM / cache behaviour of the `if bit` branches |
| What it exploits | Pure algebra; no implementation detail | A **leaky implementation** (non-constant-time double-and-add) |
| Cost | `2^bit_length(k)` — exponential; a teaching tool, not an attack on real keys | Can recover a real key from *one or few* traces if the code branches on secret bits |
| Defence | None needed — it is just slow | Constant-time code, blinding, masking |

KeyLab's walkback is the **mathematical** kind: it takes only the public key and
reverses the arithmetic, learning nothing from any implementation. It is a lens
on *why* the forward ladder works and *why* the discrete-log problem is hard — it
is **not** a power/timing attack and does not monitor branch execution. The
side-channel kind is what constant-time production libraries defend against, and
is the reason KeyLab's non-constant-time code must never touch a real secret key.
