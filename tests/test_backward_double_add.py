"""Backward double-and-add traversal and point halving (educational recovery).

All arithmetic is exact (no floating point); every recovery is cross-checked
against a forward multiplication. These tests pin the honest behaviour: halving
is exact, each step has two valid branches, and recovery costs 2**bit_length(k).
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, P, point_add_affine, point_negate_affine, scalar_mult
from keylab.recovery.backward_double_add import (
    HALF_SCALAR,
    MAX_DEPTH,
    backward_step,
    backward_traverse_to_identity,
    cost_table,
    point_halve,
    recover_via_backward,
)


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
