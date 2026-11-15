"""Mod-9 propagation layer: unit propagation + casting-out-nines conflict check.

These tests check soundness (the propagator never forces a literal that a
satisfying extension contradicts, and never reports a false conflict) against
brute force on small formulas.
"""

from __future__ import annotations

import itertools
import random

import pytest

from keylab.sat.mod9 import Mod9Group, Mod9Propagator


def _brute_force_models(clauses, max_var, partial):
    """All full assignments extending ``partial`` that satisfy every clause."""
    free = [v for v in range(1, max_var + 1) if v not in partial]
    models = []
    for bits in itertools.product((False, True), repeat=len(free)):
        assignment = dict(partial)
        assignment.update(dict(zip(free, bits)))
        if all(any((lit > 0) == assignment[abs(lit)] for lit in clause) for clause in clauses):
            models.append(assignment)
    return models


def test_unit_propagation_forces_chain() -> None:
    # 1 is forced true; (−1 ∨ 2) then forces 2; (−2 ∨ 3) forces 3.
    clauses = [(1,), (-1, 2), (-2, 3)]
    result = Mod9Propagator(clauses).propagate()
    assert result.ok
    assert result.implied == {1: True, 2: True, 3: True}


def test_unit_propagation_detects_conflict() -> None:
    result = Mod9Propagator([(1,), (-1,)]).propagate()
    assert result.conflict
    assert "all-false" in result.reason


def test_input_assignment_is_not_mutated() -> None:
    given = {1: True}
    Mod9Propagator([(-1, 2)]).propagate(given)
    assert given == {1: True}  # implied 2 must not leak back into the caller's dict


def test_mod9_rejects_unreachable_residue_immediately() -> None:
    # A single bit (weight 1) is 0 or 1 mod 9, so residue 2 is impossible.
    propagator = Mod9Propagator([(1, -1)], groups=[Mod9Group((1,), residue=2)], max_variable=1)
    result = propagator.propagate()
    assert result.conflict
    assert "mod-9" in result.reason


def test_mod9_accepts_reachable_residue() -> None:
    # bits [v1,v2] weights [1,2]; value 3 ≡ 3 (mod 9) is reachable (both set).
    propagator = Mod9Propagator(
        [(1, -1), (2, -2)], groups=[Mod9Group((1, 2), residue=3)], max_variable=2
    )
    assert propagator.propagate().ok


def test_mod9_conflict_once_bits_fix_the_residue() -> None:
    # Require residue 3 but fix the weight-2 bit false: only weight-1 remains,
    # giving residues {0,1}; 3 is now unreachable.
    propagator = Mod9Propagator(
        [(1, -1), (2, -2)], groups=[Mod9Group((1, 2), residue=3)], max_variable=2
    )
    result = propagator.propagate({2: False})
    assert result.conflict
    assert "mod-9" in result.reason


def test_rejects_zero_literal() -> None:
    with pytest.raises(ValueError, match="nonzero"):
        Mod9Propagator([(1, 0)])


def test_group_validation() -> None:
    with pytest.raises(ValueError, match="residue"):
        Mod9Group((1, 2), residue=9)
    with pytest.raises(ValueError, match="unique"):
        Mod9Group((1, 1), residue=0)


@pytest.mark.parametrize("seed", range(25))
def test_soundness_against_brute_force(seed: int) -> None:
    """No false conflict, and every implied literal holds in all real models."""
    rng = random.Random(seed)
    max_var = rng.randint(3, 5)
    clause_count = rng.randint(2, 6)
    clauses = []
    for _ in range(clause_count):
        size = rng.randint(1, 3)
        variables = rng.sample(range(1, max_var + 1), size)
        clauses.append(tuple(v if rng.random() < 0.5 else -v for v in variables))

    # Optionally pin a mod-9 group to the residue of a real model, keeping it sound.
    groups: list[Mod9Group] = []
    base_models = _brute_force_models(clauses, max_var, {})
    if base_models and rng.random() < 0.5:
        model = rng.choice(base_models)
        group_bits = tuple(rng.sample(range(1, max_var + 1), rng.randint(1, max_var)))
        value = sum(1 << i for i, b in enumerate(group_bits) if model[b])
        groups.append(Mod9Group(group_bits, residue=value % 9))

    propagator = Mod9Propagator(clauses, groups=groups, max_variable=max_var)

    partial: dict[int, bool] = {}
    for variable in range(1, max_var + 1):
        if rng.random() < 0.3:
            partial[variable] = rng.random() < 0.5

    result = propagator.propagate(partial)

    def model_matches_group(model: dict[int, bool]) -> bool:
        return all(
            sum(1 << i for i, b in enumerate(g.bits) if model[b]) % 9 == g.residue for g in groups
        )

    real_models = [m for m in _brute_force_models(clauses, max_var, partial) if model_matches_group(m)]

    if result.conflict:
        # A reported conflict must mean no satisfying extension exists (soundness).
        assert real_models == []
    else:
        # The propagator is incomplete, so "ok" with no real models is allowed;
        # but any literal it *did* force must hold in every real model.
        for variable, value in result.implied.items():
            assert all(m[variable] == value for m in real_models)
