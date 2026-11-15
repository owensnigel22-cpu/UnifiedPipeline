"""Reduced-round SHA-256 differential cryptanalysis (educational).

Heuristic XOR-differential trail search and a Dobbertin-style reduced-round
collision scaffold. No full 64-round preimage or collision is claimed; all work
targets reduced-round, constrained instances. See
:mod:`keylab.research.sha256_differential.trail_search`.
"""

from keylab.research.sha256_differential.dobbertin import (
    CollisionCandidate,
    CollisionHarness,
)
from keylab.research.sha256_differential.trail_search import (
    Trail,
    search,
    trail_from_message_difference,
    verify_by_sampling,
    xdp_add_weight,
)

__all__ = [
    "CollisionCandidate",
    "CollisionHarness",
    "Trail",
    "search",
    "trail_from_message_difference",
    "verify_by_sampling",
    "xdp_add_weight",
]
