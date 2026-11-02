"""Backward double-and-add traversal for secp256k1 (educational).

Point halving is exact on secp256k1's odd prime-order group: the unique P with
``2P = Q`` is ``((N+1)/2)*Q``, which :mod:`keylab.ec.halving` already provides as
:func:`~keylab.ec.halving.halve_point` / ``HALF_SCALAR``. Reversing the
double-and-add ladder from a public key ``Q = k*G`` is a binary tree of depth
``bit_length(k)``: at each step both predecessors

* bit 0 -> ``halve(Q)``
* bit 1 -> ``halve(Q - G)``

are valid curve points, indistinguishable by structure. Enumerating the tree to
find the path back to the identity recovers ``k``, but costs ``2**bit_length(k)``
-- it is exactly brute force, i.e. the ECDLP, with no shortcut. For a *bounded*
scalar interval use :mod:`keylab.recovery.kangaroo` (``O(sqrt(width))``) instead.

Teaching aid only: this is never selected by ``scalar_mult``, signing, or
verification, and recovers nothing that iterating ``k`` and checking ``k*G == Q``
would not. It does not threaten any 256-bit key. See SECURITY.md.
"""

from __future__ import annotations

from collections import deque
from time import perf_counter

from keylab.ec.halving import HALF_SCALAR, halve_point
from keylab.ec.secp256k1 import G, Point, point_add_affine, point_negate_affine, scalar_mult

# Above this the tree has >= 2**64 nodes: already hopelessly infeasible, so reject early.
MAX_DEPTH = 64


def point_halve(point: Point) -> Point:
    """Return the unique P with ``2P == point`` (``((N+1)/2)*point``); ``None`` stays ``None``."""
    return halve_point(point)


def backward_step(point: Point) -> tuple[Point, Point]:
    """Return the two double-and-add predecessors of ``point``: ``(halve(Q), halve(Q - G))``.

    Bit 0 came from ``Q = 2*pred``; bit 1 from ``Q = 2*pred + G``. Both are valid
    points, and nothing in the curve structure reveals which one produced ``point``.
    """
    half_zero = halve_point(point)
    half_one = halve_point(point_add_affine(point, point_negate_affine(G)))
    return half_zero, half_one


def _report(k: int | None, depth: int, leaves: int, start: float) -> dict[str, object]:
    return {
        "k": k,
        "depth": depth,
        "leaves_explored": leaves,
        "time_sec": perf_counter() - start,
        "found": k is not None,
        "method": "backward-double-and-add",
    }


def backward_traverse_to_identity(point: Point, max_depth: int) -> dict[str, object]:
    """Breadth-first reverse the ladder from ``point``, seeking the path to infinity.

    Returns a report dict whose ``k`` is the recovered scalar (``k*G == point``) or
    ``None`` when no path of length ``<= max_depth`` reaches the identity. Explores
    up to ``2**max_depth`` nodes, so it is feasible only for small ``max_depth``.
    Bits are accumulated LSB-first: branch 0 leaves the bit clear, branch 1 sets
    bit ``depth``.
    """
    if type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"max_depth must be an int in [0, {MAX_DEPTH}]")
    start = perf_counter()
    minus_g = point_negate_affine(G)
    queue: deque[tuple[Point, int, int]] = deque([(point, 0, 0)])
    leaves = 0
    while queue:
        current, depth, bits = queue.popleft()
        leaves += 1
        if current is None:  # reached the identity -> bits is k
            return _report(bits, depth, leaves, start)
        if depth >= max_depth:
            continue
        queue.append((halve_point(current), depth + 1, bits))  # bit 0
        queue.append(
            (halve_point(point_add_affine(current, minus_g)), depth + 1, bits | (1 << depth))
        )  # bit 1
    return _report(None, max_depth, leaves, start)


def recover_via_backward(point: Point, max_depth: int) -> dict[str, object]:
    """Recover the scalar behind ``point`` by backward traversal, verifying ``k*G == point``.

    Educational: the cost is ``2**bit_length(k)`` -- identical to brute force. Any
    reported ``k`` is cross-checked against a forward multiplication first, so a
    reported ``k`` is always correct (and ``None`` means not found within
    ``max_depth``).
    """
    report = backward_traverse_to_identity(point, max_depth)
    k = report["k"]
    if isinstance(k, int) and scalar_mult(k, G) != point:  # forward verification
        report["k"] = None
        report["found"] = False
    return report


def cost_table() -> list[tuple[int, int, str]]:
    """Return ``(scalar_bits, 2**bits leaves, feasibility)`` rows for the honest wall."""
    rows = []
    for bits in (8, 16, 20, 24, 32, 64, 128, 256):
        feasibility = (
            "feasible" if bits <= 20
            else "very slow" if bits <= 32
            else "infeasible" if bits <= 64
            else "ECDLP wall"
        )
        rows.append((bits, 1 << bits, feasibility))
    return rows


__all__ = [
    "HALF_SCALAR",
    "MAX_DEPTH",
    "backward_step",
    "backward_traverse_to_identity",
    "cost_table",
    "point_halve",
    "recover_via_backward",
]
