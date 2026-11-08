"""Negation-map symmetry variant of the bounded-interval kangaroo (educational).

Mathematical role: the same distinguished-point kangaroo as
:func:`keylab.research.ecdlp.kangaroo.pollard_kangaroo`, but the tame traps are
keyed by x-coordinate only, so a wild point collides whenever it lands on
``+T`` **or** ``-T`` (both share an x), exploiting the ``P == -(-P)`` symmetry.

Measured reality (do not oversell): in this tame-ahead / wild-catch design the
cost is dominated by the tame-wild *merge distance*, not by trap density, so
folding only the trap lookup yields a **measured ~1.0x** speedup over the plain
kangaroo -- not RCKangaroo's ~1.8x. That 1.8x comes from symmetric *walks*
(folding every step to the canonical representative), which require fruitless-
cycle detection and are intentionally **not** implemented here: a wrong cycle
handler would silently return incorrect scalars. This variant is therefore a
correct demonstration of the symmetry idea, not a performance win; it does not
change the ``O(2*sqrt(width))`` asymptotics or the full-group wall.

Scope boundary: an optional, in-scope optimization of the existing interval
solver; it does not widen scope, does not touch the M3 kangaroo, and does not
help a full 256-bit key. Teaching aid only; never on the signing path.

Idea source: the SOTA negation-map symmetry in RCKangaroo (RetiredCoder, GPLv3)
-- idea only, re-implemented in KeyLab's own style. See CREDITS.md.
"""

from __future__ import annotations

from time import perf_counter

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, scalar_mult
from keylab.research.ecdlp.kangaroo import _default_dp_bits, _index, _jump_distances

__all__ = ["pollard_kangaroo_symmetric"]


def pollard_kangaroo_symmetric(
    point: Point,
    lo: int,
    hi: int,
    *,
    dp_bits: int | None = None,
    max_steps: int | None = None,
) -> int | None:
    """Recover ``k`` in ``[lo, hi]`` with ``k*G == point`` using negation-map symmetry.

    Returns the forward-verified scalar or ``None`` within budget. Each tame
    distinguished point is stored by x-coordinate with its scalar and y; a wild
    collision on the shared x is resolved to ``+T`` or ``-T`` and the scalar
    recovered accordingly, so both signs are caught by one stored trap.
    """
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")
    if dp_bits is not None and (type(dp_bits) is not int or not 1 <= dp_bits <= 256):
        raise ValueError("dp_bits must be an int in [1, 256]")

    width = hi - lo
    if width == 0:
        return lo if scalar_mult(lo, G) == point else None

    eff_dp_bits = dp_bits if dp_bits is not None else _default_dp_bits(width)
    dp_mask = (1 << eff_dp_bits) - 1
    jump_distances = _jump_distances(width)
    jump_points = tuple(scalar_mult(d, G) for d in jump_distances)
    count = len(jump_distances)
    max_jump = jump_distances[-1]
    base_hops = max(16, int(2.0 * (width**0.5)) + 1)
    budget = max_steps if max_steps is not None else base_hops * 16

    # table: x-coordinate -> (tame_scalar, tame_y). Keyed by x so +T and -T map here.
    traps: dict[int, tuple[int, int]] = {}
    spent = offset = 0
    tame_hops = base_hops
    while spent < budget:
        tame_point = scalar_mult((hi + offset) % N, G)
        tame_distance = hi + offset
        for _ in range(tame_hops):
            if spent >= budget:
                return None
            if tame_point is not None and (tame_point[0] & dp_mask) == 0:
                traps.setdefault(tame_point[0], (tame_distance, tame_point[1]))
            step = _index(tame_point, count)
            tame_point = point_add_affine(tame_point, jump_points[step])
            tame_distance += jump_distances[step]
            spent += 1
        if tame_point is not None:
            traps.setdefault(tame_point[0], (tame_distance, tame_point[1]))  # forced final

        wild_point = point
        wild_distance = 0
        bound = width + (tame_distance - hi) + max_jump
        while wild_distance <= bound:
            if spent >= budget:
                return None
            if wild_point is not None and wild_point[0] in traps:
                tame_scalar, tame_y = traps[wild_point[0]]
                if wild_point[1] == tame_y:  # wild == +T
                    cand = (tame_scalar - wild_distance) % N
                else:  # shared x, opposite y -> wild == -T
                    cand = (-tame_scalar - wild_distance) % N
                if lo <= cand <= hi and scalar_mult(cand, G) == point:
                    return cand
            step = _index(wild_point, count)
            wild_point = point_add_affine(wild_point, jump_points[step])
            wild_distance += jump_distances[step]
            spent += 1
        offset += 1
        tame_hops += base_hops // 2 + 1
    return None


def compare_step_counts(point: Point, lo: int, hi: int, *, dp_bits: int | None = None) -> dict[str, object]:
    """Measurement helper: steps for the symmetric variant on one instance (timing only)."""
    start = perf_counter()
    k = pollard_kangaroo_symmetric(point, lo, hi, dp_bits=dp_bits)
    return {"k": k, "found": k is not None, "time_sec": perf_counter() - start,
            "method": "kangaroo-negation-map"}
