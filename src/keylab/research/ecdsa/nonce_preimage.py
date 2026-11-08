"""Recover a signature nonce confined to a bounded range (a nonce pre-image).

Mathematical role: a signature exposes ``r = R.x mod N`` where ``R = k*G`` is the
nonce point. If the nonce ``k`` is known to lie in a declared bounded interval
``[lo, hi]`` (e.g. a faulty RNG with low entropy), lift ``r`` to its curve point(s)
and recover ``k`` with a bounded-interval discrete-log solver
(:func:`keylab.research.ecdlp.bsgs.baby_step_giant_step` or the kangaroo).

Scope boundary: the range ``[lo, hi]`` is required and validated; this never
attempts an unbounded nonce search (that is the full ECDLP and is infeasible). It
recovers only a nonce already known to be confined to a stated interval, from a
signature the caller supplies. Teaching aid; see SECURITY.md.
"""

from __future__ import annotations

from keylab.ec.secp256k1 import G, N, P, scalar_mult
from keylab.research.ecdlp.bsgs import baby_step_giant_step
from keylab.research.ecdlp.kangaroo import pollard_kangaroo

__all__ = ["recover_nonce_in_range"]


def _lift_x(x: int) -> list[tuple[int, int]]:
    """Return the (up to two) curve points with this x-coordinate, or []."""
    if not 0 <= x < P:
        return []
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)  # P % 4 == 3, so this is the square root when one exists
    if (y * y - rhs) % P != 0:
        return []
    return [(x, y), (x, (P - y) % P)]


def recover_nonce_in_range(
    r: int, lo: int, hi: int, *, method: str = "bsgs", max_steps: int | None = None
) -> int | None:
    """Return the nonce ``k`` in ``[lo, hi]`` whose point has ``x == r (mod N)``, or ``None``.

    ``method`` is ``"bsgs"`` (deterministic) or ``"kangaroo"``. Candidate x-values
    ``r`` and ``r + N`` (if it is still a valid field element) are both lifted, so a
    nonce whose point x-coordinate exceeded ``N`` before reduction is handled.
    """
    if type(r) is not int or type(lo) is not int or type(hi) is not int:
        raise TypeError("r, lo and hi must be integers")
    if not 1 <= r < N:
        raise ValueError("r must be in [1, N-1]")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N (a bounded range is mandatory)")
    if method not in ("bsgs", "kangaroo"):
        raise ValueError("method must be 'bsgs' or 'kangaroo'")

    solve = (
        (lambda pt: baby_step_giant_step(pt, lo, hi)) if method == "bsgs"
        else (lambda pt: pollard_kangaroo(pt, lo, hi, max_steps=max_steps))
    )
    for x in (r, r + N):
        for point in _lift_x(x):
            candidate = solve(point)
            if not isinstance(candidate, int):
                continue
            recovered_point = scalar_mult(candidate, G)
            if recovered_point is not None and recovered_point == point and recovered_point[0] % N == r:
                return candidate
    return None
