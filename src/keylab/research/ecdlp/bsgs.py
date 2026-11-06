"""Baby-step giant-step (BSGS) for the bounded-interval ECDLP on secp256k1.

Mathematical role: recover ``k`` in ``[lo, hi]`` with ``k*G == point`` in a
*deterministic* ``O(sqrt(width))`` time and ``O(sqrt(width))`` memory, complementing
the probabilistic :func:`keylab.research.ecdlp.kangaroo.pollard_kangaroo` (BSGS
wins when the interval is small enough that its guaranteed runtime beats
kangaroo's expected one, and it never fails to find an in-interval ``k``).

Scope boundary: it recovers only a scalar already known to lie in the stated,
bounded interval; it does **not** derive a key from an address or attempt the
full group as a practical attack (a full-group table would need ~``2**128``
entries). Teaching aid only; never on the signing path. See SECURITY.md.
"""

from __future__ import annotations

from math import isqrt
from time import perf_counter

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, point_negate_affine, scalar_mult

__all__ = ["baby_step_giant_step", "recover_via_bsgs"]


def baby_step_giant_step(point: Point, lo: int, hi: int) -> int | None:
    """Return the unique ``k`` in ``[lo, hi]`` with ``k*G == point``, or ``None``.

    Deterministic: if such a ``k`` exists in the interval it is always found (and
    forward-verified); ``None`` means no scalar in ``[lo, hi]`` maps to ``point``.
    """
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")

    width = hi - lo
    # Reduce to [0, width]: Q' = point - lo*G, so k' = k - lo lies in [0, width].
    reduced = point_add_affine(point, point_negate_affine(scalar_mult(lo % N, G)))
    if width == 0:
        return lo if reduced is None else None

    m = isqrt(width) + 1  # ceil(sqrt(width+1)) bound: m*m > width

    # Baby steps: table of j*G -> j for j in [0, m).
    table: dict[Point, int] = {}
    current = None  # 0*G = identity
    for j in range(m):
        table.setdefault(current, j)
        current = point_add_affine(current, G)

    # Giant steps: reduced - i*(m*G) for i in [0, m]; a hit gives k' = i*m + j.
    giant_stride = point_negate_affine(scalar_mult((m % N), G))  # -m*G
    gamma = reduced
    for i in range(m + 1):
        if gamma in table:
            candidate = i * m + table[gamma]
            if candidate <= width:
                k = candidate + lo
                if scalar_mult(k, G) == point:  # forward verification
                    return k
        gamma = point_add_affine(gamma, giant_stride)
    return None


def recover_via_bsgs(point: Point, lo: int, hi: int) -> dict[str, object]:
    """Recover ``k`` in ``[lo, hi]`` via BSGS and report timing, mirroring the kangaroo API."""
    start = perf_counter()
    k = baby_step_giant_step(point, lo, hi)
    return {
        "k": k,
        "lo": lo,
        "hi": hi,
        "width": hi - lo,
        "time_sec": perf_counter() - start,
        "found": k is not None,
        "method": "baby-step-giant-step",
    }
