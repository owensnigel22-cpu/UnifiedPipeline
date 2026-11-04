"""Chained-halving shortcut -- does NOT apply to the backward_double_add traversal.

``halve_m(Q, m)`` returns the point halved ``m`` times as a single scalar
multiplication, because ``HALF_SCALAR = (N+1)//2 == 2**-1 (mod N)`` (the
authoritative constant from :mod:`keylab.ec.halving`), so an m-fold chained
halving of *one* point collapses to ``(2**-m mod N) * Q``. ``halve_m(Q, 2**20)``
returns in milliseconds (one O(1) scalar mul) versus roughly 17 minutes for the
literal ``2**20``-long chain of point halvings.

This shortcut is valid **only** for repeatedly halving a single point. It is
**not** valid for :mod:`keylab.research.ecdlp.backward_double_add`: that traversal
branches (``halve(Q)`` vs ``halve(Q - G)``) and the branches diverge, so there is
no single-scalar collapse -- use ``backward_step`` /
``backward_traverse_to_identity`` there, never ``halve_m``. The naive ``2**m``
chained version is infeasible past small ``m``; see SEC_STATE_JOURNAL.md for the
extrapolated cost at ``m = 2**20``.

Reuses the authoritative ``HALF_SCALAR``; introduces no new halving arithmetic.
"""

from __future__ import annotations

from keylab.ec.halving import HALF_SCALAR
from keylab.ec.secp256k1 import N, Point, scalar_mult


def halve_m(point: Point, m: int) -> Point:
    """Return ``point`` halved ``m`` times, as one scalar multiplication by ``2**-m mod N``.

    ``m`` must be a non-negative integer. ``m == 0`` returns ``point`` unchanged;
    ``point is None`` (the identity) returns ``None``. Does not apply to the
    branching backward traversal (see the module docstring).
    """
    if type(m) is not int or m < 0:
        raise ValueError("m must be a non-negative integer")
    if point is None:
        return None
    return scalar_mult(pow(HALF_SCALAR, m, N), point)


__all__ = ["halve_m"]
