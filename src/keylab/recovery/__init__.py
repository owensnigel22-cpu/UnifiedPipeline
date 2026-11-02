"""Educational scalar-recovery demonstrations for secp256k1.

These are teaching aids, not attacks. ``backward_double_add`` reverses the
double-and-add ladder (exactly the ECDLP; cost ``2**bit_length(k)``), and
``kangaroo`` solves the *bounded-interval* ECDLP in ``O(sqrt(width))``. Neither is
selected by ``scalar_mult``, signing, or verification, and neither dents a full
256-bit key. See SECURITY.md.
"""

from __future__ import annotations

from keylab.recovery.backward_double_add import (
    HALF_SCALAR,
    backward_step,
    backward_traverse_to_identity,
    cost_table,
    point_halve,
    recover_via_backward,
)
from keylab.recovery.kangaroo import pollard_kangaroo, recover_via_kangaroo

__all__ = [
    "HALF_SCALAR",
    "backward_step",
    "backward_traverse_to_identity",
    "cost_table",
    "point_halve",
    "pollard_kangaroo",
    "recover_via_backward",
    "recover_via_kangaroo",
]
