"""Reduced-round SHA-256 preimage research (19/20-step), strictly bounded.

Two layers, both reduced-round only — **no full 64-round preimage is claimed or
attempted** (that remains infeasible):

- :mod:`~keylab.research.sha256_reduced.register_window` — deterministic,
  forward-verified compression preimages for 8..16 rounds (the schedule-free
  regime), via the a-register sliding-window identity.
- :mod:`~keylab.research.sha256_reduced.context_shaping` — a faithful port of the
  srw/pre19.c 19-step context-shaping search (Basra's triangularization + Q-table).
  Reference-correct and forward-verifying, but a full pure-Python 19/20-step search
  is impractical (see that module's performance note). The same module's
  :func:`~keylab.research.sha256_reduced.search_17_step_preimage` *is* feasible in
  pure Python — a 17-round instance has a single schedule constraint, solved by a
  meet-in-the-middle in seconds, and is exercised live in the test suite.
- :mod:`~keylab.research.sha256_reduced.published` — genuine published 19/20-step
  witnesses from the reference repos, verified against the reduced-round reference.

See ``docs/references.md`` for attribution to the ported MIT-licensed work.
"""

from __future__ import annotations

from keylab.research.sha256_reduced.context_shaping import (
    ShapingResult,
    build_q_table,
    search_17_step_preimage,
    search_19_step_preimage,
)
from keylab.research.sha256_reduced.published import (
    PUBLISHED_VECTORS,
    SRW_ABC_19_STEP,
    SRW_ABC_20_STEP,
    PublishedPreimage,
)
from keylab.research.sha256_reduced.register_window import (
    CompressionPreimage,
    reduced_compress,
    register_window_preimage,
)

__all__ = [
    "PUBLISHED_VECTORS",
    "SRW_ABC_19_STEP",
    "SRW_ABC_20_STEP",
    "CompressionPreimage",
    "PublishedPreimage",
    "ShapingResult",
    "build_q_table",
    "reduced_compress",
    "register_window_preimage",
    "search_17_step_preimage",
    "search_19_step_preimage",
]
