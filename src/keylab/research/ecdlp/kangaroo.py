"""Pollard's kangaroo (lambda) method for the bounded-interval ECDLP on secp256k1.

Given ``Q = k*G`` with ``k`` known to lie in ``[lo, hi]``, recover ``k`` in roughly
``O(sqrt(hi - lo))`` group operations instead of the ``O(hi - lo)`` of brute force.
This is the correct tool the backward-traversal demo points to: for a 32-bit
interval it is ~``2**16`` hops versus ~``2**32``. Passing the full group
``[0, N-1]`` as the interval makes it a full-group ECDLP attempt -- same walk,
~``2**128`` expected hops -- which does not dent a 256-bit key.

The walk is deterministic given its parameters and any candidate is forward-
verified (``k*G == Q``) before it is returned, so a returned ``k`` is always
correct and ``None`` means the run did not collide within budget. Teaching aid
only; never on the production signing path. See SECURITY.md.

``max_steps`` bounds the **total** hops (tame + wild, across retries): a
budget-bounded call with ``max_steps`` far below the natural ``~2*sqrt(width)``
returns ``None`` early after spending exactly ``max_steps`` hops. This is
expected and is the correct behaviour for bounded measurement of the full-group
wall (see scripts/benchmark_ecdlp.py and docs/research/ecdlp_benchmark.md).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, scalar_mult

try:  # resource is POSIX-only; memory reporting is best-effort off-Linux.
    import resource as _resource
except ImportError:  # pragma: no cover - Windows/dev
    _resource = None  # type: ignore[assignment]


@dataclass(frozen=True)
class KangarooResult:
    """State of a kangaroo run, returned when ``return_state=True``.

    ``dps_found`` is always 0: this is a single moving-trap (tame/wild) kangaroo,
    not a distinguished-point table variant, so there is no DP set to count. It
    is reported for a uniform benchmark schema. ``memory_peak_bytes`` is ``None``
    where ``resource`` is unavailable (e.g. Windows).
    """

    solution: int | None
    spent_steps: int
    dps_found: int
    memory_peak_bytes: int | None
    attempts_used: int


def _jump_distances(width: int) -> tuple[int, ...]:
    """Powers-of-two jump set sized so the mean jump is on the order of ``sqrt(width)``."""
    count = max(2, width.bit_length() // 2 + 1)
    return tuple(1 << i for i in range(count))


def _index(point: Point, modulus: int) -> int:
    return 0 if point is None else point[0] % modulus


def _peak_memory_bytes() -> int | None:
    # getattr avoids a mypy attr-defined error on platforms (e.g. Windows) whose
    # `resource` stub lacks these POSIX-only names; None where unavailable.
    if _resource is None:
        return None
    getrusage = getattr(_resource, "getrusage", None)
    rusage_self = getattr(_resource, "RUSAGE_SELF", None)
    if getrusage is None or rusage_self is None:
        return None
    # Linux reports KiB; assume KiB (the CI platform).
    return int(getrusage(rusage_self).ru_maxrss) * 1024


def _run_once(
    point: Point,
    hi: int,
    width: int,
    jump_distances: tuple[int, ...],
    jump_points: tuple[Point, ...],
    tame_hops: int,
    offset: int,
    hop_budget: int,
    spent_base: int,
    progress_callback: Callable[[int, int], None] | None,
    progress_every: int,
) -> tuple[int | None, int]:
    """One tame/wild kangaroo pair, bounded to ``hop_budget`` hops.

    Returns ``(candidate_or_None, hops_used)``. Stops and returns ``None`` once
    ``hop_budget`` hops are spent, so a caller with a small budget on a huge
    interval spends exactly its budget instead of running ~``2*sqrt(width)`` hops.
    """
    count = len(jump_distances)
    hops = 0

    # Tame kangaroo: start at the right end of the interval and set a trap.
    tame_point = scalar_mult((hi + offset) % N, G)
    tame_distance = hi + offset
    for _ in range(tame_hops):
        if hops >= hop_budget:
            return None, hops
        step = _index(tame_point, count)
        tame_point = point_add_affine(tame_point, jump_points[step])
        tame_distance += jump_distances[step]
        hops += 1
        if progress_callback is not None and (spent_base + hops) % progress_every == 0:
            progress_callback(spent_base + hops, 0)

    # Wild kangaroo: start at Q and walk forward until it lands on the trap.
    wild_point = point
    wild_distance = 0
    bound = width + (tame_distance - hi) + jump_distances[-1]
    while wild_distance <= bound:
        if hops >= hop_budget:
            return None, hops
        if wild_point == tame_point:
            return tame_distance - wild_distance, hops
        step = _index(wild_point, count)
        wild_point = point_add_affine(wild_point, jump_points[step])
        wild_distance += jump_distances[step]
        hops += 1
        if progress_callback is not None and (spent_base + hops) % progress_every == 0:
            progress_callback(spent_base + hops, 0)
    return None, hops


def pollard_kangaroo(
    point: Point,
    lo: int,
    hi: int,
    *,
    max_steps: int | None = None,
    return_state: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
    progress_every: int = 100_000,
) -> int | None | KangarooResult:
    """Recover ``k`` in ``[lo, hi]`` with ``k*G == point`` via Pollard's kangaroo.

    Returns the forward-verified scalar, or ``None`` if no collision occurs within
    the step budget. ``max_steps`` caps the **total** tame+wild hops across
    retries (default: a generous multiple of ``sqrt(width)``); once it is reached
    the walk stops and returns ``None`` -- for a very large width (e.g. the full
    secp256k1 group) a call with ``max_steps`` well below ``~2*sqrt(width)``
    returns early after spending exactly ``max_steps`` hops, which is the correct
    bounded-measurement behaviour.

    With ``return_state=True`` a :class:`KangarooResult` is returned instead of a
    bare scalar (existing callers using the default are unchanged).
    ``progress_callback(spent_hops, dps)`` is invoked every ``progress_every``
    hops for long runs (e.g. to flush a partial record on SIGTERM).
    """
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")

    def _result(solution: int | None, spent: int, attempts: int) -> int | None | KangarooResult:
        if return_state:
            return KangarooResult(solution, spent, 0, _peak_memory_bytes(), attempts)
        return solution

    width = hi - lo
    if width == 0:
        found = lo if scalar_mult(lo, G) == point else None
        return _result(found, 0, 0)

    jump_distances = _jump_distances(width)
    jump_points = tuple(scalar_mult(distance, G) for distance in jump_distances)
    base_hops = max(16, int(2.0 * (width ** 0.5)) + 1)
    budget = max_steps if max_steps is not None else base_hops * 16

    offset = 0
    spent = 0
    attempts = 0
    tame_hops = base_hops
    while spent < budget:
        candidate, used = _run_once(
            point, hi, width, jump_distances, jump_points, tame_hops, offset,
            budget - spent, spent, progress_callback, progress_every,
        )
        spent += used
        attempts += 1
        if candidate is not None and lo <= candidate <= hi and scalar_mult(candidate, G) == point:
            return _result(candidate, spent, attempts)
        # Perturb the trap and lengthen the walk, then retry.
        offset += 1
        tame_hops += base_hops // 2 + 1
    return _result(None, spent, attempts)


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


__all__ = ["KangarooResult", "pollard_kangaroo", "recover_via_kangaroo"]
