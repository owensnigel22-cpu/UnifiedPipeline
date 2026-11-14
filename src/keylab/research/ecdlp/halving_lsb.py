"""LSB-leak interval-shrink attack by point halving (educational side-channel demo).

If a side channel leaks the least-significant bits of a secret scalar ``k`` (with
``Q = k*G``), point halving turns each leaked bit into an exact interval halving.
For the low bit ``b0`` of ``k``::

    k = 2*k1 + b0   =>   k1*G = (Q - b0*G) / 2 = HALF_SCALAR * (Q - b0*G)

where ``HALF_SCALAR = (N+1)//2`` is the authoritative constant from
:mod:`keylab.ec.halving`. Repeating this for ``m`` leaked bits yields
``Q_m = (k >> m) * G`` and the exact low ``m`` bits of ``k``; the remaining high
part lives in a window shrunk by ``2**m``, which is then recovered by a short
incremental walk. Contrast this with
:mod:`keylab.research.ecdlp.backward_double_add`, whose *blind* predecessor tree
costs ``2**bit_length(k)`` — the leak is exactly what collapses that to linear work.

Teaching aid only: it recovers nothing that knowing the leaked bits plus a small
brute force would not, and threatens no real 256-bit key without a real side
channel. Demonstrated on secp256k1 with a bounded ("toy"-sized) scalar, since point
halving requires the real group order. See ``SECURITY.md``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from keylab.ec.halving import halve_point
from keylab.ec.secp256k1 import G, N, Point, point_add_affine, point_negate_affine, scalar_mult

_NEG_G: Point = point_negate_affine(G)


@dataclass(frozen=True)
class HalvingLSBResult:
    """Outcome of an LSB-leak interval-shrink halving attack."""

    recovered_scalar: int | None
    verified: bool
    leaked_bits: int
    low_bits_value: int
    high_window_width: int
    steps: list[dict[str, object]] = field(default_factory=list)


def lsb_halving_attack(
    public_key: Point,
    leaked_lsbs: Sequence[int],
    *,
    interval: tuple[int, int] = (0, N - 1),
    max_high_window: int = 1 << 20,
) -> HalvingLSBResult:
    """Recover ``k`` from ``Q = k*G`` given its ``leaked_lsbs`` (bit 0 first).

    Each leaked bit halves the problem via ``HALF_SCALAR``; the shrunk high window
    ``[L >> m, U >> m]`` is then swept incrementally (one point add per candidate)
    to pin the high part and forward-verify ``k*G == Q``. ``leaked_lsbs`` are the
    true low bits of ``k`` (as a side channel would reveal). Raises if the residual
    high window exceeds ``max_high_window`` (keep the demo bounded).
    """
    low, high = interval
    if not (type(low) is int and type(high) is int and 0 <= low <= high < N):
        raise ValueError("interval must be (low, high) with 0 <= low <= high < N")
    bits = list(leaked_lsbs)
    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("leaked_lsbs must each be 0 or 1")

    current: Point = public_key
    low_value = 0
    steps: list[dict[str, object]] = []
    for index, bit in enumerate(bits):
        shifted = point_add_affine(current, _NEG_G) if bit else current
        current = halve_point(shifted)
        low_value |= bit << index
        steps.append({
            "step": index,
            "bit": bit,
            "operation": "halve(Q - G)" if bit else "halve(Q)",
            "low_bits_recovered": low_value,
        })

    leaked = len(bits)
    high_low = low >> leaked
    high_high = high >> leaked
    window = high_high - high_low + 1
    if window > max_high_window:
        raise ValueError(
            f"residual high window {window} exceeds max_high_window {max_high_window}; "
            "leak more bits or narrow the interval"
        )

    recovered: int | None = None
    verified = False
    walker: Point = scalar_mult(high_low, G)
    for high_candidate in range(high_low, high_high + 1):
        if walker == current:
            candidate = (high_candidate << leaked) | low_value
            if scalar_mult(candidate, G) == public_key:
                recovered = candidate
                verified = True
                break
        walker = point_add_affine(walker, G)

    return HalvingLSBResult(
        recovered_scalar=recovered,
        verified=verified,
        leaked_bits=leaked,
        low_bits_value=low_value,
        high_window_width=window,
        steps=steps,
    )


def demo_instance(secret: int = 0xC0FFEE, leaked_bits: int = 12) -> dict[str, object]:
    """Build a secp256k1 demo: pick a bounded secret, leak its low bits, recover it.

    Returns a JSON-friendly summary including the recovered scalar and verification.
    """
    if not 1 <= secret < N:
        raise ValueError("secret must be in [1, N)")
    if not 1 <= leaked_bits <= secret.bit_length():
        raise ValueError("leaked_bits must be between 1 and the secret's bit length")
    public_key = scalar_mult(secret, G)
    lsbs = [(secret >> i) & 1 for i in range(leaked_bits)]
    interval = (0, (1 << secret.bit_length()) - 1)
    result = lsb_halving_attack(public_key, lsbs, interval=interval)
    return {
        "secret_bit_length": secret.bit_length(),
        "leaked_bits": leaked_bits,
        "high_window_width": result.high_window_width,
        "recovered": result.recovered_scalar,
        "verified": result.verified,
        "recovered_matches_secret": result.recovered_scalar == secret,
    }


__all__ = [
    "HalvingLSBResult",
    "demo_instance",
    "lsb_halving_attack",
]
