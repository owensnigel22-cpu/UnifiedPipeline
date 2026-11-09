"""Memory-bounded meet-in-the-middle search over a bounded secp256k1 interval.

This is an educational variable-time search, not a full-key recovery tool. A
search unit is one baby-table insertion or one giant-step table lookup. Setup
scalar multiplications and forward verification are included in the wall-time
budget but excluded from ``spent_steps``. The table contains at most
``max_memory_entries`` points. A failed search consumes an explicit step budget
exactly; after an exhaustive pass, remaining units repeat the giant lookups.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite, isqrt
from time import perf_counter

from keylab.ec.secp256k1 import (
    G,
    N,
    Point,
    is_on_curve,
    point_add_affine,
    point_negate_affine,
    scalar_mult,
)


@dataclass(frozen=True)
class MITMResult:
    """Bounded MITM outcome, including explicit work and memory accounting."""

    solution: int | None
    spent_steps: int
    baby_steps: int
    giant_steps: int
    table_entries: int
    search_complete: bool
    stop_reason: str
    elapsed_seconds: float


def meet_in_the_middle_bounded(
    point: Point,
    lo: int,
    hi: int,
    *,
    max_steps: int | None = None,
    max_memory_entries: int = 65_536,
    max_seconds: float | None = None,
    return_state: bool = False,
) -> int | None | MITMResult:
    """Find ``k`` in ``[lo, hi]`` such that ``k*G == point`` using MITM.

    The interval is decomposed as ``k = lo + a + b*m``. The baby table stores
    ``a*G`` for ``0 <= a < m`` and each giant lookup checks
    ``point - lo*G - b*m*G``. ``m`` is at most the memory-entry limit and near
    ``sqrt(hi-lo+1)`` when memory permits.

    ``max_steps`` counts table insertions and giant candidate lookups. On a
    failed search, an explicit step allowance is consumed exactly unless the
    wall-time deadline expires. ``max_seconds`` is checked between work units;
    point-multiplication setup and verification are not interruptible but do
    count toward elapsed time. ``return_state=True`` returns an :class:`MITMResult`.
    """
    if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi < N:
        raise ValueError("require integer bounds 0 <= lo <= hi < N")
    if point is not None and not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    if type(max_memory_entries) is not int or max_memory_entries < 1:
        raise ValueError("max_memory_entries must be a positive int")
    if max_steps is not None and (type(max_steps) is not int or max_steps < 0):
        raise ValueError("max_steps must be a nonnegative int")
    if max_seconds is not None and (
        type(max_seconds) not in (int, float) or not isfinite(max_seconds) or max_seconds <= 0
    ):
        raise ValueError("max_seconds must be a positive finite number")

    started = perf_counter()
    width = hi - lo + 1
    baby_count = min(isqrt(width - 1) + 1, max_memory_entries)
    giant_count = (width + baby_count - 1) // baby_count
    natural_steps = baby_count + giant_count
    budget = natural_steps if max_steps is None else max_steps
    spent = baby_steps = giant_steps = 0
    table_entries = 0
    search_complete = False

    def result(solution: int | None, reason: str) -> int | None | MITMResult:
        state = MITMResult(
            solution=solution,
            spent_steps=spent,
            baby_steps=baby_steps,
            giant_steps=giant_steps,
            table_entries=table_entries,
            search_complete=search_complete,
            stop_reason=reason,
            elapsed_seconds=perf_counter() - started,
        )
        return state if return_state else state.solution

    def timed_out() -> bool:
        return max_seconds is not None and perf_counter() - started >= max_seconds

    if budget == 0:
        return result(None, "step_budget")

    # Shift the target so the search interval begins at zero, and prepare m*G.
    shifted = point_add_affine(point, point_negate_affine(scalar_mult(lo, G)))
    stride_point = scalar_mult(baby_count, G)
    if timed_out():
        return result(None, "time_budget")

    baby_table: dict[Point, int] = {}
    current: Point = None
    for a in range(baby_count):
        if spent >= budget:
            break
        if timed_out():
            return result(None, "time_budget")
        baby_table.setdefault(current, a)
        table_entries = len(baby_table)
        baby_steps += 1
        spent += 1
        if a + 1 < baby_count:
            current = point_add_affine(current, G)

    if table_entries < baby_count:
        return result(None, "step_budget")

    # Build complete giant passes. Repeating a pass consumes a larger explicit
    # budget without ever growing the baby table beyond its configured limit.
    while spent < budget:
        gamma = shifted
        pass_checks = 0
        for b in range(giant_count):
            if spent >= budget:
                break
            if timed_out():
                return result(None, "time_budget")
            a = baby_table.get(gamma)
            giant_steps += 1
            spent += 1
            pass_checks += 1
            if a is not None:
                candidate = lo + a + b * baby_count
                if candidate <= hi and scalar_mult(candidate, G) == point:
                    return result(candidate, "found")
            if b + 1 < giant_count:
                gamma = point_add_affine(gamma, point_negate_affine(stride_point))
        if pass_checks == giant_count:
            search_complete = True
        if max_steps is None or spent >= budget:
            break

    reason = "step_budget" if max_steps is not None else "search_complete"
    return result(None, reason)


__all__ = ["MITMResult", "meet_in_the_middle_bounded"]
