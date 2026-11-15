"""Probabilistic and algebraic reduced-round SHA-256 solvers (M15, Phase C).

Two independent, strictly reduced-round tools — **no full 64-round preimage is
claimed or attempted**:

- :mod:`~keylab.research.sha256_prob.belief_propagation` — a correct loopy
  sum-product belief-propagation engine over binary factor graphs, applied to a
  *truncated*, reduced-round preimage problem. The engine is exact on trees
  (tested against brute-force marginals); loopy BP on the hash circuit has **no**
  convergence guarantee, so :func:`~belief_propagation.solve_truncated` reports
  ``converged``/``verified`` honestly and forward-verifies every decoded candidate.
- :mod:`~keylab.research.sha256_prob.sha256_milp` — a pure-Python MILP *emitter*
  for the reduced-round compression as a bit-level 0/1 model (CPLEX ``.lp`` and
  ``.mps`` text, no solver dependency). ``MILPModel.solve()`` is optional and needs
  the ``milp`` extra (``pip install keylab[milp]``, which pulls in ``pulp``); it is
  skipped cleanly when ``pulp`` is absent.

See ``docs/references.md`` for attribution (hirorylabo/preimage-attacks,
trevphil/cryptosym).
"""

from __future__ import annotations

from keylab.research.sha256_prob.belief_propagation import (
    BPResult,
    Factor,
    FactorGraph,
    solve_truncated,
)
from keylab.research.sha256_prob.sha256_milp import (
    Constraint,
    MILPModel,
    MILPVariable,
    compression_milp,
)

__all__ = [
    "BPResult",
    "Constraint",
    "Factor",
    "FactorGraph",
    "MILPModel",
    "MILPVariable",
    "compression_milp",
    "solve_truncated",
]
