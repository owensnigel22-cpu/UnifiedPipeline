"""19-step SHA-256 preimage search by context shaping (a faithful port of pre19.c).

This is a line-by-line Python port of the CPU solver ``src/pre19.c`` from
``srw/sha256-19-and-20-step-preimages-with-padding`` (MIT), crediting the
context-shaping idea to K. S. Basra. See ``docs/references.md``.

**Method.** The ``a``-register sequence is pinned at the start by the IV and at
the end by the target (both through the sliding-window identity in
:mod:`keylab.research.sha256_reduced.register_window`). Context words
``a_5..a_11`` are chosen so that ``e_9 = e_10 = 0xffffffff``, which makes the
three message-schedule constraints for ``W_16, W_17, W_18`` *triangular*: each is
``Q(W_i) = target_i`` for ``Q(u) = sigma0(u) - u``, solved in turn through a
partial inverse table of ``Q``. In padded mode the length words and the ``0x80``
marker are absorbed algebraically so the block is a real 55-byte-message preimage.
Every candidate is run through the full 19-round compression and only returned if
it reproduces the target (:func:`_compress`), so a returned result is always valid.

**Honest performance note.** The inverse table covers only ``2**(table_bits - 32)``
of the 32-bit range, so the per-chain success probability is about
``coverage**3 * (3/4)**32``. In C with a ``2**28``-plus table and GPUs this is
milliseconds; **in pure Python a full 19-step search is impractical** — a feasible
table (``table_bits <= 24``, since larger ones are too slow/large to build in
Python) leaves roughly ``2**37`` chains to walk. This port is therefore for study,
for validating the technique, and for driving the C/CUDA reference for real
searches; it is not a fast pure-Python preimage finder. Nothing here touches full
64-round SHA-256, which remains infeasible.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from keylab.hashes.reduced import _SHA_IV, _SHA_K

_MASK = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF
_ROUNDS = 19
_OFF = 7  # a[t] is stored at index t + _OFF; t ranges over [-7, 19]
_PADLEN_BITS = 440  # a 55-byte message occupies the final block (55*8 = 440 bits)
_IV = tuple(_SHA_IV)


def _ror(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << ((-count) & 31))) & _MASK


def _big_sigma0(x: int) -> int:
    return _ror(x, 2) ^ _ror(x, 13) ^ _ror(x, 22)


def _big_sigma1(x: int) -> int:
    return _ror(x, 6) ^ _ror(x, 11) ^ _ror(x, 25)


def _small_sigma0(x: int) -> int:
    return _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)


def _small_sigma1(x: int) -> int:
    return _ror(x, 17) ^ _ror(x, 19) ^ (x >> 10)


def _maj(a: int, b: int, c: int) -> int:
    return (a & b) ^ (a & c) ^ (b & c)


def _ch(e: int, f: int, g: int) -> int:
    return (e & f) ^ (~e & g & _MASK)


def _q(u: int) -> int:
    """Q(u) = sigma0(u) - u, the function the triangular schedule inverts."""
    return (_small_sigma0(u) - u) & _MASK


class _SplitMix64:
    """The exact splitmix64 generator used by pre19.c, for reproducible seeds."""

    def __init__(self, seed: int) -> None:
        self._state = (seed * 0x2545F4914F6CDD1D + 7) & _U64

    def next64(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & _U64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _U64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _U64
        return z ^ (z >> 31)

    def next32(self) -> int:
        return self.next64() & _MASK


def build_q_table(table_bits: int) -> dict[int, list[int]]:
    """Build a partial inverse of ``Q``: ``Q(u) -> sampled u`` (up to 8 per value).

    Samples ``2**table_bits`` points of the 32-bit domain. Coverage of the range
    is about ``2**(table_bits - 32)``; see the module performance note.
    """
    if type(table_bits) is not int or not 1 <= table_bits <= 31:
        raise ValueError("table_bits must be between 1 and 31")
    table: dict[int, list[int]] = {}
    for index in range(1 << table_bits):
        u = (index * 0x9E3779B1) & _MASK
        bucket = table.setdefault(_q(u), [])
        if len(bucket) < 8:
            bucket.append(u)
    return table


def window_from_state(state: tuple[int, ...]) -> list[int]:
    """Return ``a_{r-7..r}`` for a register state ``(a0..a3, e0..e3)`` (window identity)."""
    if len(state) != 8:
        raise ValueError("state must have 8 words")
    a = [state[0], state[1], state[2], state[3], 0, 0, 0, 0]
    e = state[4:8]
    for k in range(4):
        a[4 + k] = (e[k] - a[k] + _big_sigma0(a[k + 1]) + _maj(a[k + 1], a[k + 2], a[k + 3])) & _MASK
    return [a[7 - i] for i in range(8)]


def _compress(words: list[int], rounds: int) -> list[int]:
    """Full ``rounds``-round SHA-256 compression with feed-forward (final verifier)."""
    schedule = list(words) + [0] * (64 - len(words))
    for t in range(16, rounds):
        schedule[t] = (
            _small_sigma1(schedule[t - 2])
            + schedule[t - 7]
            + _small_sigma0(schedule[t - 15])
            + schedule[t - 16]
        ) & _MASK
    a, b, c, d, e, f, g, h = _IV
    for t in range(rounds):
        t1 = (h + _big_sigma1(e) + _ch(e, f, g) + _SHA_K[t] + schedule[t]) & _MASK
        t2 = (_big_sigma0(a) + _maj(a, b, c)) & _MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK
    return [(value + _IV[i]) & _MASK for i, value in enumerate((a, b, c, d, e, f, g, h))]


@dataclass(frozen=True)
class ShapingResult:
    """Outcome of a 19-step context-shaping search."""

    found: bool
    mode: str
    target: bytes
    block: bytes | None
    message: bytes | None
    contexts: int
    chains: int
    elapsed_seconds: float
    verified: bool


class _NineteenStepSolver:
    """Holds the ``a``-sequence and evaluates the ported ``E``/``Wt`` identities."""

    def __init__(self) -> None:
        self.a = [0] * (_ROUNDS + _OFF + 2)

    def e(self, step: int) -> int:
        a = self.a
        i = step + _OFF
        return (a[i] - _big_sigma0(a[i - 1]) - _maj(a[i - 1], a[i - 2], a[i - 3]) + a[i - 4]) & _MASK

    def w(self, step: int) -> int:
        et = self.e(step)
        return (
            self.e(step + 1)
            - self.a[step - 3 + _OFF]
            - self.e(step - 3)
            - _big_sigma1(et)
            - _ch(et, self.e(step - 1), self.e(step - 2))
            - _SHA_K[step]
        ) & _MASK


def search_19_step_preimage(
    target_digest: bytes,
    *,
    mode: str = "padded",
    table_bits: int = 22,
    seed: int = 1,
    kmax: int = 3,
    max_contexts: int = 64,
    chains_per_context: int = 1 << 14,
    time_budget: float = 10.0,
) -> ShapingResult:
    """Search for a 19-step SHA-256 preimage of ``target_digest`` by context shaping.

    ``mode`` is ``"padded"`` (the block is a real 55-byte-message preimage) or
    ``"comp"`` (the compression output, message words free). The search is bounded
    by ``max_contexts``, ``chains_per_context`` and ``time_budget`` seconds; it
    returns a :class:`ShapingResult` whose ``found`` says whether a forward-verified
    preimage was produced within the budget. See the module note: a full search is
    impractical in pure Python, so a short budget will usually return ``found=False``
    — that is the honest behaviour, not an error.
    """
    if len(target_digest) != 32:
        raise ValueError("target_digest must be exactly 32 bytes")
    if mode not in ("padded", "comp"):
        raise ValueError("mode must be 'padded' or 'comp'")
    if type(kmax) is not int or not 1 <= kmax <= 8:
        raise ValueError("kmax must be between 1 and 8")

    padded = mode == "padded"
    table = build_q_table(table_bits)
    rng = _SplitMix64(seed)
    solver = _NineteenStepSolver()
    a = solver.a

    for i, value in enumerate(window_from_state(_IV)):
        a[i] = value  # a_{-7..0}
    digest = tuple(int.from_bytes(target_digest[i : i + 4], "big") for i in range(0, 32, 4))
    state = tuple((digest[i] - _IV[i]) & _MASK for i in range(8))
    for i, value in enumerate(window_from_state(state)):
        a[(_ROUNDS - 7 + i) + _OFF] = value  # a_{12..19}

    start = time.monotonic()
    contexts = chains = 0
    for _ in range(max_contexts):
        if time.monotonic() - start > time_budget:
            break
        difference = _setup_context(solver, rng, padded, kmax, start, time_budget)
        if difference is None:
            break  # ran out of time inside context setup
        contexts += 1
        result = _walk_chains(
            solver, table, rng, difference, padded, target_digest, digest,
            chains_per_context, start, time_budget,
        )
        if result is not None:
            block, message = result
            return ShapingResult(
                True, mode, target_digest, block, message, contexts,
                chains + 1, time.monotonic() - start, verified=True,
            )
        chains += chains_per_context
    return ShapingResult(
        False, mode, target_digest, None, None, contexts, chains,
        time.monotonic() - start, verified=False,
    )


def _setup_context(
    solver: _NineteenStepSolver, rng: _SplitMix64, padded: bool, kmax: int,
    start: float, time_budget: float,
) -> int | None:
    """Choose context words so e_9 = e_10 = 0xffffffff; return D = a_5 ^ a_6 or None on timeout."""
    a = solver.a
    if not padded:
        v = rng.next32()
        a[5 + _OFF] = v
        a[6 + _OFF] = v
        a[7 + _OFF] = rng.next32()
        a[8 + _OFF] = rng.next32()
        a[11 + _OFF] = rng.next32()
        a[9 + _OFF] = (0xFFFFFFFF + _big_sigma0(a[8 + _OFF]) + _maj(a[8 + _OFF], a[7 + _OFF], a[6 + _OFF]) - a[5 + _OFF]) & _MASK
        a[10 + _OFF] = (0xFFFFFFFF + _big_sigma0(a[9 + _OFF]) + _maj(a[9 + _OFF], a[8 + _OFF], a[7 + _OFF]) - a[6 + _OFF]) & _MASK
        return 0
    while True:
        if time.monotonic() - start > time_budget:
            return None
        a[9 + _OFF] = rng.next32()
        a[10 + _OFF] = rng.next32()
        a[11 + _OFF] = rng.next32()
        a[8 + _OFF] = 0
        a[8 + _OFF] = (solver.w(15) - (_PADLEN_BITS & _MASK)) & _MASK  # force W15 = low word of bit length
        a[7 + _OFF] = 0
        a[7 + _OFF] = (solver.w(14) - ((_PADLEN_BITS >> 32) & _MASK)) & _MASK  # force W14 = high word
        a[6 + _OFF] = (0xFFFFFFFF - a[10 + _OFF] + _big_sigma0(a[9 + _OFF]) + _maj(a[9 + _OFF], a[8 + _OFF], a[7 + _OFF])) & _MASK
        a[5 + _OFF] = a[4 + _OFF] = a[3 + _OFF] = a[2 + _OFF] = 0
        if (solver.w(13) & 0xFF) != 0x80:
            continue
        a[5 + _OFF] = (0xFFFFFFFF - a[9 + _OFF] + _big_sigma0(a[8 + _OFF]) + _maj(a[8 + _OFF], a[7 + _OFF], a[6 + _OFF])) & _MASK
        difference = a[5 + _OFF] ^ a[6 + _OFF]
        if difference.bit_count() <= kmax:
            return difference


def _walk_chains(
    solver: _NineteenStepSolver, table: dict[int, list[int]], rng: _SplitMix64,
    difference: int, padded: bool, target_digest: bytes, digest: tuple[int, ...],
    chains_per_context: int, start: float, time_budget: float,
) -> tuple[bytes, bytes] | None:
    """Walk the three-level W1/W2/W3 chain; return (block, message) on a verified hit."""
    a = solver.a
    a[1 + _OFF] = a[2 + _OFF] = a[3 + _OFF] = a[4 + _OFF] = 0
    c9, c10, c11 = solver.w(9), solver.w(10), solver.w(11)
    w14, w15, w16, w17, w18 = (solver.w(t) for t in (14, 15, 16, 17, 18))
    t16 = (w16 - _small_sigma1(w14) - c9) & _MASK
    t17 = (w17 - _small_sigma1(w15) - c10) & _MASK
    t18 = (w18 - _small_sigma1(w16) - c11) & _MASK
    base = rng.next32()
    for i in range(chains_per_context):
        if (i & 0x3FFF) == 0 and time.monotonic() - start > time_budget:
            return None
        a[1 + _OFF] = (base + i) & _MASK
        a[2 + _OFF] = 0
        w0 = solver.w(0)
        g1 = (0 - solver.w(1)) & _MASK
        for cand1 in table.get((t16 + g1 - w0) & _MASK, ()):
            a[2 + _OFF] = (cand1 + g1) & _MASK
            a[3 + _OFF] = 0
            g2 = (0 - solver.w(2)) & _MASK
            for cand2 in table.get((t17 + g2 - cand1) & _MASK, ()):
                a[3 + _OFF] = (cand2 + g2) & _MASK
                a[4 + _OFF] = 0
                g3 = (0 - solver.w(3)) & _MASK
                for cand3 in table.get((t18 + g3 - cand2) & _MASK, ()):
                    a4 = (cand3 + g3) & _MASK
                    if (_maj(a[5 + _OFF], a4, a[3 + _OFF]) - a4) & _MASK != 0:
                        continue
                    if a4 & difference:
                        continue
                    a[4 + _OFF] = a4
                    words = [solver.w(t) for t in range(16)]
                    out = _compress(words, _ROUNDS)
                    if any(out[k] != digest[k] for k in range(8)):
                        continue
                    if padded and not (
                        (words[13] & 0xFF) == 0x80
                        and words[14] == ((_PADLEN_BITS >> 32) & _MASK)
                        and words[15] == (_PADLEN_BITS & _MASK)
                    ):
                        continue
                    block = b"".join(word.to_bytes(4, "big") for word in words)
                    message = block[:55] if padded else block
                    return block, message
    return None


__all__ = [
    "ShapingResult",
    "build_q_table",
    "search_19_step_preimage",
    "window_from_state",
]
