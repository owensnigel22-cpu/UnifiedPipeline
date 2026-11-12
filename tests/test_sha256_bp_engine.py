"""Belief-propagation engine: exact on trees, sane on small loopy graphs."""

from __future__ import annotations

import itertools

import pytest

from keylab.research.sha256_prob import Factor, FactorGraph
from keylab.research.sha256_prob.belief_propagation import run_bp


def _brute_marginals(graph: FactorGraph) -> list[list[float]]:
    totals = [[0.0, 0.0] for _ in range(graph.num_vars)]
    partition = 0.0
    for bits in itertools.product((0, 1), repeat=graph.num_vars):
        weight = 1.0
        for factor in graph.factors:
            index = sum((bits[v] & 1) << k for k, v in enumerate(factor.variables))
            weight *= factor.table[index]
        partition += weight
        for v in range(graph.num_vars):
            totals[v][bits[v]] += weight
    return [[value / partition for value in pair] for pair in totals]


def test_factor_validates_table_length() -> None:
    with pytest.raises(ValueError, match="2\\*\\*len"):
        Factor((0, 1), (1.0, 0.0, 1.0))


def test_bp_is_exact_on_a_tree() -> None:
    # Chain v0 - v1 - v2 with a unary bias and two agreement factors (a tree).
    graph = FactorGraph(3, [
        Factor((0,), (0.3, 0.7)),
        Factor((0, 1), (2.0, 1.0, 1.0, 2.0)),
        Factor((1, 2), (2.0, 1.0, 1.0, 2.0)),
    ])
    beliefs, _converged, _iters = run_bp(graph, max_iters=100, damping=0.0)
    exact = _brute_marginals(graph)
    for v in range(3):
        assert beliefs[v][1] == pytest.approx(exact[v][1], abs=1e-9)


def test_bp_exact_on_a_larger_tree() -> None:
    # A small binary tree: 0 is the root, 1 and 2 its children.
    graph = FactorGraph(3, [
        Factor((0,), (0.5, 0.5)),
        Factor((0, 1), (3.0, 1.0, 1.0, 2.0)),
        Factor((0, 2), (1.0, 2.0, 2.0, 1.0)),
    ])
    beliefs, _c, _i = run_bp(graph, max_iters=200, damping=0.0)
    exact = _brute_marginals(graph)
    for v in range(3):
        assert beliefs[v][1] == pytest.approx(exact[v][1], abs=1e-9)


def test_bp_hard_pin_is_respected() -> None:
    # A hard unary pin forces its variable; a connected agreement factor should pull
    # the neighbour the same way.
    graph = FactorGraph(2, [
        Factor((0,), (0.0, 1.0)),            # pin v0 = 1
        Factor((0, 1), (4.0, 1.0, 1.0, 4.0)),  # strong agreement
    ])
    beliefs, _c, _i = run_bp(graph, max_iters=100, damping=0.0)
    assert beliefs[0][1] == pytest.approx(1.0, abs=1e-9)
    assert beliefs[1][1] > 0.5  # pulled toward 1


def test_bp_converges_on_a_single_loop() -> None:
    # A 3-cycle of agreement factors is loopy; BP should still settle (symmetric).
    graph = FactorGraph(3, [
        Factor((0, 1), (2.0, 1.0, 1.0, 2.0)),
        Factor((1, 2), (2.0, 1.0, 1.0, 2.0)),
        Factor((0, 2), (2.0, 1.0, 1.0, 2.0)),
    ])
    beliefs, converged, _iters = run_bp(graph, max_iters=300, damping=0.5, tol=1e-9)
    assert converged
    for v in range(3):
        assert beliefs[v][1] == pytest.approx(0.5, abs=1e-6)  # symmetric -> unbiased


def test_run_bp_validates_damping() -> None:
    graph = FactorGraph(1, [Factor((0,), (0.5, 0.5))])
    with pytest.raises(ValueError, match="damping"):
        run_bp(graph, damping=1.0)
