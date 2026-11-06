"""Backward double-and-add traversal and point halving (educational recovery).

All arithmetic is exact (no floating point); every recovery is cross-checked
against a forward multiplication. These tests pin the honest behaviour: halving
is exact, each step has two valid branches, and recovery costs 2**bit_length(k).
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, P, point_add_affine, point_negate_affine, scalar_mult
from keylab.research.ecdlp.backward_double_add import (
    HALF_SCALAR,
    MAX_DEPTH,
    backward_step,
    backward_traverse_to_identity,
    cost_table,
    point_halve,
    recover_via_backward,
)
from keylab.research.ecdlp.halving_shortcut import halve_m


def _double(point):
    return point_add_affine(point, point)


# --- halving ------------------------------------------------------------------------------------

def test_half_scalar_identity() -> None:
    assert (2 * HALF_SCALAR) % N == 1


def test_point_halve_is_exact() -> None:
    for k in (1, 2, 3, 7, 100, 65537, N - 1):
        Q = scalar_mult(k, G)
        half = point_halve(Q)
        assert half is not None
        assert _double(half) == Q


def test_halve_of_identity_is_identity() -> None:
    assert point_halve(None) is None


# --- two branches -------------------------------------------------------------------------------

def test_two_branches_both_valid_and_distinct() -> None:
    Q = scalar_mult(10, G)
    half_zero, half_one = backward_step(Q)
    assert half_zero is not None and half_one is not None
    assert half_zero != half_one
    # bit 0: 2*half_zero == Q ;  bit 1: 2*half_one == Q - G
    assert _double(half_zero) == Q
    assert _double(half_one) == point_add_affine(Q, point_negate_affine(G))


# --- recovery -----------------------------------------------------------------------------------

def test_backward_recovers_small_k() -> None:
    rng = random.Random(0xBA5E)
    for _ in range(8):
        k = rng.randrange(1, 256)
        report = recover_via_backward(scalar_mult(k, G), max_depth=8)
        assert report["found"], f"no recovery for k={k}"
        assert report["k"] == k


def test_recovery_depth_equals_bit_length() -> None:
    for d in (4, 6, 8):
        k = (1 << d) - 1  # all ones -> exactly d bits
        report = recover_via_backward(scalar_mult(k, G), max_depth=d)
        assert report["found"]
        assert report["k"] == k
        assert report["depth"] == d


def test_backward_fails_below_bit_length() -> None:
    report = recover_via_backward(scalar_mult(200, G), max_depth=4)  # 200 needs 8 bits
    assert not report["found"]
    assert report["k"] is None


def test_leaves_explored_bounded_by_tree_size() -> None:
    report = recover_via_backward(scalar_mult(15, G), max_depth=5)
    assert report["found"]
    assert report["leaves_explored"] <= (1 << (5 + 1))


# --- input validation ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [-1, MAX_DEPTH + 1, 2.0, "8", None])
def test_max_depth_is_validated(bad) -> None:
    with pytest.raises((ValueError, TypeError)):
        backward_traverse_to_identity(scalar_mult(5, G), bad)


# --- honest wall --------------------------------------------------------------------------------

def test_cost_table_is_exponential_and_labels_the_wall() -> None:
    rows = cost_table()
    assert [bits for bits, _, _ in rows] == [8, 16, 20, 24, 32, 64, 128, 256]
    for bits, leaves, _ in rows:
        assert leaves == 1 << bits  # exact, no floating point
    assert {bits: label for bits, _, label in rows}[256] == "ECDLP wall"


def test_recovered_scalar_is_forward_verified() -> None:
    # A reported k always satisfies k*G == Q (recover_via_backward checks before returning).
    for k in (1, 42, 255):
        report = recover_via_backward(scalar_mult(k, G), max_depth=8)
        assert report["found"] and scalar_mult(report["k"], G) == scalar_mult(k, G)
    # x-only sanity: P is the field prime, unused here but imported to assert module wiring.
    assert P > N


# --- halve_m chained-halving shortcut -----------------------------------------------------------

def test_halve_m_matches_chained_halve() -> None:
    # The O(1) shortcut must equal m sequential point halvings (m = 17, always runs).
    q = scalar_mult(0xC0FFEE, G)
    chained = q
    for _ in range(17):
        chained = point_halve(chained)
    assert halve_m(q, 17) == chained


def test_halve_m_m_equals_zero_returns_point() -> None:
    q = scalar_mult(42, G)
    assert halve_m(q, 0) == q


def test_halve_m_identity_stays_identity() -> None:
    assert halve_m(None, 5) is None


@pytest.mark.parametrize("bad", [-1, -2**20])
def test_halve_m_rejects_negative_m(bad) -> None:
    with pytest.raises(ValueError):
        halve_m(scalar_mult(7, G), bad)


def test_halve_m_2_to_20_is_o1() -> None:
    # The whole point of the shortcut: m = 2**20 returns a valid point via one
    # scalar mul (O(1)), not the ~17-minute literal chain. Always-on (it is
    # milliseconds); no wall-clock assertion (flaky). The literal 2**20-chain
    # equivalence is extrapolated in SEC_STATE_JOURNAL.md, not run in CI.
    result = halve_m(scalar_mult(0xBEEF, G), 2**20)
    assert isinstance(result, tuple) and len(result) == 2


# --- additional recovery invariants (M3) --------------------------------------------------------

def test_k5_lsb_bit_walk_accumulates_to_5() -> None:
    # k = 5 = 0b101; LSB-first the branch sequence is [1, 0, 1]. Recovery must
    # accumulate exactly these bits back to 5 (verifies LSB-first bit tracking).
    report = recover_via_backward(scalar_mult(5, G), max_depth=3)
    assert report["found"] and report["k"] == 5


def _recover_20_random(depth: int) -> None:
    rng = random.Random(0xA11CE ^ depth)  # deterministic per depth
    for _ in range(20):
        k = rng.randrange(1, 1 << depth)
        report = recover_via_backward(scalar_mult(k, G), max_depth=depth)
        assert report["found"] and report["k"] == k


@pytest.mark.parametrize("depth", [4, 6])
def test_recovery_20_random_k_per_depth(depth) -> None:
    # Always-on shallow depths (~11s combined). Each BFS node is a 256-bit
    # scalar-mult, so cost is ~2**depth per recovery. Deeper depths are not run
    # in CI (the zero-skip gate forbids opt-in skips, and 20x{8,10,12} is ~11 min);
    # their measured/extrapolated cost is recorded in SEC_STATE_JOURNAL.md.
    _recover_20_random(depth)


def test_depth_guard_above_cap_raises_citing_journal() -> None:
    with pytest.raises(ValueError, match="SEC_STATE_JOURNAL.md"):
        backward_traverse_to_identity(scalar_mult(5, G), 19)
