"""Pollard's kangaroo (lambda) method for the bounded-interval ECDLP on secp256k1.

Given ``Q = k*G`` with ``k`` known to lie in ``[lo, hi]``, recover ``k`` in roughly
``O(2*sqrt(hi - lo))`` group operations instead of the ``O(hi - lo)`` of brute
force. This is the correct tool the backward-traversal demo points to: for a
32-bit interval it is ~``2**16`` hops versus ~``2**32``. Passing the full group
``[0, N-1]`` as the interval makes it a full-group ECDLP attempt -- same walk,
~``2**128`` expected hops -- which does not dent a 256-bit key.

Distinguished-point (DP) variant
--------------------------------
This is the two-role DP kangaroo, **not** a single moving trap. The *tame*
kangaroo starts from a known scalar ahead of the interval and records every
**distinguished point** it visits -- a point whose x-coordinate has its low
``dp_bits`` bits zero, so a fraction ``1/2**dp_bits`` of points qualify -- into a
table keyed by the point, storing the tame scalar there. The *wild* kangaroo
starts at ``Q`` and walks the same deterministic jump function; once it merges
onto the tame trajectory it reaches a recorded distinguished point and the
collision yields ``k = tame_scalar - wild_distance`` (forward-verified before it
is returned). The table's size is bounded by ``spent_steps / 2**dp_bits`` rather
than by the number of hops, which is the whole point of the DP variant:
**bounded memory and resumability, not speed.**

Honest framing: the DP variant is **not faster** than a single trap. The
asymptotics are identical, ``O(2*sqrt(width))``; what changes is that memory is
bounded by the DP density and a run can be checkpointed and resumed. A 60s
full-group run still reaches only ~``2**-109`` of the work either way.

``max_steps`` bounds the **total** hops (tame + wild, across retries): a
budget-bounded call with ``max_steps`` far below the natural ``~2*sqrt(width)``
returns ``None`` early after spending exactly ``max_steps`` hops. This is
expected and is the correct behaviour for bounded measurement of the full-group
wall (see scripts/benchmark_ecdlp.py and docs/research/ecdlp_benchmark.md).

The walk is deterministic given its parameters and any candidate is forward-
verified (``k*G == Q``) before it is returned, so a returned ``k`` is always
correct and ``None`` means the run did not collide within budget. Single
process only (no multiprocessing): deterministic and cross-platform. Teaching
aid only; never on the production signing path. See SECURITY.md.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from keylab.ec.secp256k1 import G, N, Point, point_add_affine, scalar_mult

try:  # resource is POSIX-only; memory reporting is best-effort off-Linux.
    import resource as _resource
except ImportError:  # pragma: no cover - Windows/dev
    _resource = None  # type: ignore[assignment]

_CHECKPOINT_VERSION = 1


@dataclass(frozen=True)
class KangarooResult:
    """State of a kangaroo run, returned when ``return_state=True``.

    ``dps_found`` / ``dp_table_size`` count the distinguished points the tame
    role recorded (the two are equal; ``dps_found`` is kept for the uniform
    benchmark schema). ``memory_peak_bytes`` is ``None`` where ``resource`` is
    unavailable (e.g. Windows). ``walkers_used`` is always 1 -- this is a
    single-process kangaroo; the field exists for schema stability. ``last_tame``
    / ``last_wild`` are the final tame scalar and wild distance, ``last_hop`` the
    total hops, for the end-of-run state block. ``checkpoint_path`` is the file a
    budget-exhausted run flushed its resumable state to, else ``None``.
    """

    solution: int | None
    spent_steps: int
    dps_found: int
    memory_peak_bytes: int | None
    attempts_used: int
    dp_table_size: int = 0
    last_tame: int | None = None
    last_wild: int | None = None
    last_hop: int = 0
    elapsed_sec: float = 0.0
    walkers_used: int = 1
    checkpoint_path: str | None = None


def _jump_distances(width: int) -> tuple[int, ...]:
    """Powers-of-two jump set sized so the mean jump is on the order of ``sqrt(width)``."""
    count = max(2, width.bit_length() // 2 + 1)
    return tuple(1 << i for i in range(count))


def _index(point: Point, modulus: int) -> int:
    return 0 if point is None else point[0] % modulus


def _is_distinguished(point: Point, dp_mask: int) -> bool:
    """A point is distinguished iff the low ``dp_bits`` of its x-coordinate are zero."""
    return point is not None and (point[0] & dp_mask) == 0


def _default_dp_bits(width: int) -> int:
    """Pick ``dp_bits`` so the mean DP gap is well under the ~2*sqrt(width) walk.

    ``width.bit_length()//2 - 2`` gives a gap of ~``sqrt(width)/4``, i.e. several
    distinguished points per walk, so the wild role reliably reaches one.
    """
    return max(1, width.bit_length() // 2 - 2)


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


# --- checkpointing (single-process, cross-platform; no OS signal involved) ----------------------

def _point_to_json(point: Point) -> list[int] | None:
    return None if point is None else [point[0], point[1]]


def _point_from_json(value: list[int] | None) -> Point:
    return None if value is None else (int(value[0]), int(value[1]))


def save_checkpoint(path: str | os.PathLike[str], state: dict[str, Any]) -> None:
    """Atomically write a resumable kangaroo state to ``path`` as JSON.

    Atomic (temp file + ``os.replace``) so a crash mid-write never leaves a
    truncated checkpoint. Big integers are stored as strings to stay exact.
    """
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=target.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def load_checkpoint(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load a checkpoint written by :func:`save_checkpoint`."""
    with open(path, encoding="utf-8") as fh:
        state: dict[str, Any] = json.load(fh)
    if state.get("version") != _CHECKPOINT_VERSION:
        raise ValueError(f"unsupported checkpoint version: {state.get('version')!r}")
    return state


def _serialize(
    *,
    lo: int, hi: int, dp_bits: int, budget: int, point: Point,
    phase: str, tame_point: Point, tame_distance: int, tame_remaining: int, tame_hops: int,
    wild_point: Point, wild_distance: int, wild_bound: int,
    dp_table: dict[tuple[int, int], int], spent: int, offset: int, attempts: int, elapsed: float,
) -> dict[str, Any]:
    return {
        "version": _CHECKPOINT_VERSION,
        "lo": str(lo), "hi": str(hi), "dp_bits": dp_bits, "budget": str(budget),
        "point": _point_to_json(point), "phase": phase,
        "tame_point": _point_to_json(tame_point), "tame_distance": str(tame_distance),
        "tame_remaining": tame_remaining, "tame_hops": tame_hops,
        "wild_point": _point_to_json(wild_point), "wild_distance": str(wild_distance),
        "wild_bound": str(wild_bound),
        "dp_table": [[p[0], p[1], str(d)] for p, d in dp_table.items()],
        "spent": spent, "offset": offset, "attempts": attempts, "elapsed": elapsed,
    }


def pollard_kangaroo(
    point: Point,
    lo: int,
    hi: int,
    *,
    dp_bits: int | None = None,
    max_steps: int | None = None,
    return_state: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
    progress_every: int = 100_000,
    checkpoint_path: str | os.PathLike[str] | None = None,
    resume_from: str | os.PathLike[str] | None = None,
) -> int | None | KangarooResult:
    """Recover ``k`` in ``[lo, hi]`` with ``k*G == point`` via the DP kangaroo.

    Returns the forward-verified scalar, or ``None`` if no collision occurs within
    the step budget. ``max_steps`` caps the **total** tame+wild hops across
    retries; once it is reached the walk stops and returns ``None`` -- for a very
    large width (e.g. the full secp256k1 group) a call with ``max_steps`` well
    below ``~2*sqrt(width)`` returns early after spending exactly ``max_steps``
    hops, which is the correct bounded-measurement behaviour.

    ``dp_bits`` sets the distinguished-point density (a point is distinguished
    when the low ``dp_bits`` of its x-coordinate are zero, so density is
    ``1/2**dp_bits``); it defaults to a width-dependent value. ``checkpoint_path``
    flushes a resumable JSON state when the budget is exhausted; ``resume_from``
    restores such a state and continues the identical deterministic walk.

    With ``return_state=True`` a :class:`KangarooResult` is returned instead of a
    bare scalar (existing callers using the default are unchanged).
    ``progress_callback(spent_hops, dp_table_size)`` is invoked every
    ``progress_every`` hops for long runs (e.g. to flush a partial record).
    """
    start = perf_counter()
    if type(lo) is not int or type(hi) is not int:
        raise TypeError("lo and hi must be integers")
    if not 0 <= lo <= hi < N:
        raise ValueError("require 0 <= lo <= hi < N")
    if dp_bits is not None and (type(dp_bits) is not int or not 1 <= dp_bits <= 256):
        raise ValueError("dp_bits must be an int in [1, 256]")

    width = hi - lo

    def _result(
        solution: int | None, spent: int, attempts: int, dp_size: int,
        last_tame: int | None, last_wild: int | None, cp: str | None,
    ) -> int | None | KangarooResult:
        if return_state:
            return KangarooResult(
                solution=solution, spent_steps=spent, dps_found=dp_size,
                memory_peak_bytes=_peak_memory_bytes(), attempts_used=attempts,
                dp_table_size=dp_size, last_tame=last_tame, last_wild=last_wild,
                last_hop=spent, elapsed_sec=perf_counter() - start, walkers_used=1,
                checkpoint_path=cp,
            )
        return solution

    if width == 0:
        found = lo if scalar_mult(lo, G) == point else None
        return _result(found, 0, 0, 0, None, None, None)

    eff_dp_bits = dp_bits if dp_bits is not None else _default_dp_bits(width)
    dp_mask = (1 << eff_dp_bits) - 1
    jump_distances = _jump_distances(width)
    jump_points = tuple(scalar_mult(distance, G) for distance in jump_distances)
    count = len(jump_distances)
    max_jump = jump_distances[-1]
    base_hops = max(16, int(2.0 * (width ** 0.5)) + 1)
    budget = max_steps if max_steps is not None else base_hops * 16

    dp_table: dict[tuple[int, int], int] = {}

    if resume_from is not None:
        st = load_checkpoint(resume_from)
        phase = str(st["phase"])
        tame_point = _point_from_json(st["tame_point"])
        tame_distance = int(st["tame_distance"])
        tame_remaining = int(st["tame_remaining"])
        tame_hops = int(st["tame_hops"])
        wild_point = _point_from_json(st["wild_point"])
        wild_distance = int(st["wild_distance"])
        wild_bound = int(st["wild_bound"])
        for x, y, d in st["dp_table"]:
            dp_table[(int(x), int(y))] = int(d)
        spent = int(st["spent"])
        offset = int(st["offset"])
        attempts = int(st["attempts"])
    else:
        phase = "tame"
        spent = 0
        offset = 0
        attempts = 1
        tame_hops = base_hops
        tame_point = scalar_mult((hi + offset) % N, G)
        tame_distance = hi + offset
        tame_remaining = tame_hops
        wild_point = point
        wild_distance = 0
        wild_bound = 0

    def _flush(solution: int | None) -> int | None | KangarooResult:
        cp: str | None = None
        if checkpoint_path is not None:
            save_checkpoint(checkpoint_path, _serialize(
                lo=lo, hi=hi, dp_bits=eff_dp_bits, budget=budget, point=point,
                phase=phase, tame_point=tame_point, tame_distance=tame_distance,
                tame_remaining=tame_remaining, tame_hops=tame_hops, wild_point=wild_point,
                wild_distance=wild_distance, wild_bound=wild_bound, dp_table=dp_table,
                spent=spent, offset=offset, attempts=attempts, elapsed=perf_counter() - start,
            ))
            cp = str(checkpoint_path)
        return _result(
            solution, spent, attempts, len(dp_table), tame_distance,
            wild_distance if phase == "wild" else None, cp,
        )

    while spent < budget:
        if phase == "tame":
            if tame_remaining == 0:
                if tame_point is not None:
                    dp_table[tame_point] = tame_distance  # forced final trap
                wild_point = point
                wild_distance = 0
                wild_bound = width + (tame_distance - hi) + max_jump
                phase = "wild"
                continue
            if tame_point is not None and _is_distinguished(tame_point, dp_mask):
                dp_table.setdefault(tame_point, tame_distance)
            step = _index(tame_point, count)
            tame_point = point_add_affine(tame_point, jump_points[step])
            tame_distance += jump_distances[step]
            tame_remaining -= 1
            spent += 1
            if progress_callback is not None and spent % progress_every == 0:
                progress_callback(spent, len(dp_table))
        else:  # wild
            if wild_point is not None and wild_point in dp_table:
                candidate = (dp_table[wild_point] - wild_distance) % N
                if lo <= candidate <= hi and scalar_mult(candidate, G) == point:
                    return _flush(candidate)
            if wild_distance > wild_bound:
                offset += 1
                tame_hops += base_hops // 2 + 1
                tame_point = scalar_mult((hi + offset) % N, G)
                tame_distance = hi + offset
                tame_remaining = tame_hops
                attempts += 1
                phase = "tame"
                continue
            step = _index(wild_point, count)
            wild_point = point_add_affine(wild_point, jump_points[step])
            wild_distance += jump_distances[step]
            spent += 1
            if progress_callback is not None and spent % progress_every == 0:
                progress_callback(spent, len(dp_table))

    return _flush(None)


def recover_via_kangaroo(
    point: Point, lo: int, hi: int, *, dp_bits: int | None = None, max_steps: int | None = None,
) -> dict[str, object]:
    """Recover ``k`` in ``[lo, hi]`` and report timing, as a dict mirroring the backward API."""
    start = perf_counter()
    k = pollard_kangaroo(point, lo, hi, dp_bits=dp_bits, max_steps=max_steps)
    return {
        "k": k,
        "lo": lo,
        "hi": hi,
        "width": hi - lo,
        "time_sec": perf_counter() - start,
        "found": k is not None,
        "method": "pollard-kangaroo",
    }


__all__ = [
    "KangarooResult",
    "load_checkpoint",
    "pollard_kangaroo",
    "recover_via_kangaroo",
    "save_checkpoint",
]
