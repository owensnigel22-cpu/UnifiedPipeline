"""Tests for the bounded, memory-limited MITM ECDLP demonstration."""

from __future__ import annotations

from keylab.ec.secp256k1 import G, point_add_affine, scalar_mult
from keylab.research.cryptanalysis.mitm_ecdlp import MITMResult, meet_in_the_middle_bounded


def test_mitm_recovers_bounded_key_with_fewer_search_units_than_brute_force() -> None:
    secret = 1_000
    upper_bound = 8_191
    target = scalar_mult(secret, G)
    result = meet_in_the_middle_bounded(
        target,
        0,
        upper_bound,
        max_memory_entries=64,
        return_state=True,
    )

    assert isinstance(result, MITMResult)
    assert result.solution == secret
    assert result.search_complete is False  # found before exhausting all giant candidates
    assert result.table_entries <= 64

    # Count the direct group additions needed by a straightforward interval scan.
    current = None
    brute_force_steps = 0
    for candidate in range(upper_bound + 1):
        if current == target:
            assert candidate == secret
            break
        current = point_add_affine(current, G)
        brute_force_steps += 1
    assert result.spent_steps < brute_force_steps


def test_mitm_honors_exact_step_budget_and_memory_limit_on_failure() -> None:
    result = meet_in_the_middle_bounded(
        scalar_mult(9_000, G),
        10_000,
        20_000,
        max_steps=250,
        max_memory_entries=64,
        return_state=True,
    )
    assert isinstance(result, MITMResult)
    assert result.solution is None
    assert result.spent_steps == 250
    assert result.table_entries <= 64
    assert result.search_complete is True
    assert result.stop_reason == "step_budget"


def test_mitm_stops_inside_baby_table_at_exact_small_budget() -> None:
    result = meet_in_the_middle_bounded(
        scalar_mult(9_000, G),
        10_000,
        20_000,
        max_steps=7,
        max_memory_entries=64,
        return_state=True,
    )
    assert isinstance(result, MITMResult)
    assert result.solution is None
    assert result.spent_steps == 7
    assert result.table_entries == 7
    assert result.search_complete is False
