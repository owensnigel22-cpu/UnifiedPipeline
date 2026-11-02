"""Pollard's kangaroo (lambda) method for the bounded-interval ECDLP on secp256k1.

Given ``Q = k*G`` with ``k`` known to lie in ``[lo, hi]``, recover ``k`` in roughly
``O(sqrt(hi - lo))`` group operations instead of the ``O(hi - lo)`` of brute force.
This is the correct tool the backward-traversal demo points to: for a 32-bit
interval it is ~``2**16`` hops versus ~``2**32``. It does **not** dent a full
256-bit key -- that interval needs ~``2**128`` hops.

The walk is deterministic given its parameters and any candidate is forward-
verified (``k*G == Q``) before it is returned, so a returned ``k`` is always
correct and ``None`` means the run did not collide within budget. Teaching aid
only; never on the production signing path. See SECURITY.md.
"""

from __future__ import annotations

from time import perf_counter

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, scalar_mult


def _jump_distances(width: int) -> tuple[int, ...]:
    """Powers-of-two jump set sized so the mean jump is on the order of ``sqrt(width)``."""
    count = max(2, width.bit_length() // 2 + 1)
    return tuple(1 << i for i in range(count))


def _index(point: Point, modulus: int) -> int:
    return 0 if point is None else point[0] % modulus


def _run_once(
    point: Point,
    hi: int,
    width: int,
    jump_distances: tuple[int, ...],
    jump_points: tuple[Point, ...],
    tame_hops: int,
    offset: int,
) -> int | None:
    """One tame/wild kangaroo pair. Returns a candidate scalar or ``None`` on no collision."""
    count = len(jump_distances)
    # Tame kangaroo: start at the right end of the interval and set a trap.
    tame_point = scalar_mult((hi + offset) % N, G)
    tame_distance = hi + offset
    for _ in range(tame_hops):
        step = _index(tame_point, count)
        tame_point = point_add_affine(tame_point, jump_points[step])
        tame_distance += jump_distances[step]

    # Wild kangaroo: start at Q and walk forward until it lands on the trap.
    wild_point = point
    wild_distance = 0
    bound = width + (tame_distance - hi) + jump_distances[-1]
    while wild_distance <= bound:
        if wild_point == tame_point:
            return tame_distance - wild_distance
        step = _index(wild_point, count)
        wild_point = point_add_affine(wild_point, jump_points[step])
        wild_distance += jump_distances[step]
    return None


def pollard_kangaroo(point: Point, lo: int, hi: int, *, max_steps: int | None = None) -> int | None:
    """Recover ``k`` in ``[lo, hi]`` with ``k*G == point`` via Pollard's kangaroo.

    Returns the forward-verified scalar, or ``None`` if no collision occurs within
    the step budget. ``max_steps`` caps the total tame hops across retries (default:
    a generous multiple of ``sqrt(width)``).
    """
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")
    width = hi - lo
    if width == 0:
        return lo if scalar_mult(lo, G) == point else None

    jump_distances = _jump_distances(width)
    jump_points = tuple(scalar_mult(distance, G) for distance in jump_distances)
    base_hops = max(16, int(2.0 * (width ** 0.5)) + 1)
    budget = max_steps if max_steps is not None else base_hops * 16

    offset = 0
    spent = 0
    tame_hops = base_hops
    while spent < budget:
        candidate = _run_once(point, hi, width, jump_distances, jump_points, tame_hops, offset)
        spent += tame_hops
        if candidate is not None and lo <= candidate <= hi and scalar_mult(candidate, G) == point:
            return candidate
        # Perturb the trap and lengthen the walk, then retry.
        offset += 1
        tame_hops += base_hops // 2 + 1
    return None


def recover_via_kangaroo(point: Point, lo: int, hi: int, *, max_steps: int | None = None) -> dict[str, object]:
    """Recover ``k`` in ``[lo, hi]`` and report timing, as a dict mirroring the backward API."""
    start = perf_counter()
    k = pollard_kangaroo(point, lo, hi, max_steps=max_steps)
    return {
        "k": k,
        "lo": lo,
        "hi": hi,
        "width": hi - lo,
        "time_sec": perf_counter() - start,
        "found": k is not None,
        "method": "pollard-kangaroo",
    }


__all__ = ["pollard_kangaroo", "recover_via_kangaroo"]
