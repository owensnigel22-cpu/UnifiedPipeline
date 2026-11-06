"""Pollard's rho for the discrete-logarithm problem (educational).

Mathematical role: find ``k`` with ``target == k*base`` in a cyclic group of known
prime ``order`` using a pseudo-random walk with Floyd cycle detection, in
``O(sqrt(order))`` expected steps and ``O(1)`` memory -- a different
time/memory tradeoff from the baby-step giant-step table and from the kangaroo.

Scope boundary: classic rho solves the **full-group** DLP; its cost is
``sqrt(order)`` of the whole group and it does **not** exploit a bounded interval
(that is the kangaroo's / BSGS's advantage). On secp256k1 (prime order ``N``) a
full-group rho is therefore a ``~2**128`` attempt that no budget shortens -- it is
provided as the full-group method and as a correctness-checkable rho, not as a
practical attack. Teaching aid only; never on the signing path. See SECURITY.md.

Idea source: Pollard's rho (1978); the rho+lambda pairing and secp256k1 framing
follow the MIT-licensed ``gec`` library (HareInWeed/gec) -- idea only, re-
implemented. See CREDITS.md.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, point_negate_affine, scalar_mult

__all__ = ["RhoResult", "pollard_rho", "pollard_rho_dlog"]


@dataclass(frozen=True)
class RhoResult:
    """State of a rho run (returned when ``return_state=True``)."""

    solution: int | None
    spent_steps: int
    collisions: int
    elapsed_sec: float


def _partition(point: object, hasher: Callable[[object], int]) -> int:
    return hasher(point) % 3


def pollard_rho_dlog(
    add: Callable[[object, object], object],
    base: object,
    target: object,
    order: int,
    *,
    hasher: Callable[[object], int],
    max_steps: int | None = None,
    seed: int = 1,
) -> int | None:
    """Return ``k`` with ``target == k*base`` in a cyclic group of prime ``order``.

    Generic over the group: ``add`` composes two elements, ``hasher`` maps an
    element to an int (for the 3-way partition), ``base``/``target`` are elements.
    Returns ``None`` if no collision is reached within ``max_steps`` steps or the
    collision is degenerate (caller may retry with a different ``seed``).
    """
    if type(order) is not int or order < 2:
        raise ValueError("order must be an int >= 2")

    def step(point: object, a: int, b: int) -> tuple[object, int, int]:
        branch = _partition(point, hasher)
        if branch == 0:
            return add(point, base), (a + 1) % order, b
        if branch == 1:
            return add(point, point), (2 * a) % order, (2 * b) % order
        return add(point, target), a, (b + 1) % order

    budget = max_steps if max_steps is not None else 8 * (int(order**0.5) + 1)
    # Start the walk at seed*base (a=seed, b=0) so retries explore different trails.
    start = base
    sa = seed % order
    for _ in range(sa - 1 if sa > 0 else 0):
        start = add(start, base)
    tx, ta, tb = start, sa, 0  # tortoise
    hx, ha, hb = start, sa, 0  # hare
    spent = 0
    while spent < budget:
        tx, ta, tb = step(tx, ta, tb)
        hx, ha, hb = step(*step(hx, ha, hb))
        spent += 2
        if tx == hx:
            denom = (hb - tb) % order
            if denom == 0:
                return None  # degenerate; caller retries with another seed
            k = (ta - ha) * pow(denom, -1, order) % order
            return k
    return None


def pollard_rho(
    point: Point,
    lo: int,
    hi: int,
    *,
    max_steps: int | None = None,
    return_state: bool = False,
) -> int | None | RhoResult:
    """Recover ``k`` in ``[lo, hi]`` with ``k*G == point`` via full-group Pollard rho.

    Reduces to ``k' = k - lo`` and solves the discrete log of ``point - lo*G`` over
    the whole group. Because rho does not exploit the interval, a bounded
    ``max_steps`` well below ``sqrt(N)`` returns ``None`` after spending roughly
    that many steps -- the correct behaviour for a full-group measurement.
    """
    start_t = perf_counter()
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")

    reduced = point_add_affine(point, point_negate_affine(scalar_mult(lo % N, G)))

    def _hash(pt: object) -> int:
        return 0 if pt is None else int(pt[0])  # type: ignore[index]

    spent_holder = {"n": 0}

    def _add(a: object, b: object) -> object:
        spent_holder["n"] += 1
        return point_add_affine(a, b)  # type: ignore[arg-type]

    kprime: int | None = None
    collisions = 0
    for seed in range(1, 4):  # a few restarts to dodge degenerate collisions
        cand = pollard_rho_dlog(
            _add, G, reduced, N, hasher=_hash,
            max_steps=max_steps, seed=seed,
        )
        if cand is not None:
            collisions += 1
            k = (cand + lo) % N
            if lo <= k <= hi and scalar_mult(k, G) == point:  # forward verification
                kprime = k
                break
        if max_steps is not None:
            break  # a single bounded measurement, not a multi-restart solve

    if return_state:
        return RhoResult(kprime, spent_holder["n"], collisions, perf_counter() - start_t)
    return kprime
