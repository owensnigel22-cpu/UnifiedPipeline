"""Educational bounded-interval discrete-log demonstrations for secp256k1.

These functions operate on bounded intervals of public inputs. They do not
recover real wallet keys, do not process signatures, and do not produce
spendable artifacts.

Teaching aids, not attacks. ``backward_double_add`` reverses the double-and-add
ladder (exactly the ECDLP; cost ``2**bit_length(k)``), and ``kangaroo`` solves
the *bounded-interval* ECDLP in ``O(sqrt(width))``. Neither is selected by
``scalar_mult``, signing, or verification, and neither dents a full 256-bit key.
See SECURITY.md.
"""

from __future__ import annotations

from keylab.research.ecdlp.backward_double_add import (
    HALF_SCALAR,
    backward_step,
    backward_traverse_to_identity,
    cost_table,
    point_halve,
    recover_via_backward,
)
from keylab.research.ecdlp.kangaroo import pollard_kangaroo, recover_via_kangaroo

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
