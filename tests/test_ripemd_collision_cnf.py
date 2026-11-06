"""Reduced-round RIPEMD-160 collision CNF (educational, reduced-round only).

The SAT solution is verified against an INDEPENDENT reference: the from-scratch
reduced-round compression `keylab.hashes.reduced.ripemd160_reduced`. A solved
pair must (a) differ and (b) have equal reduced-round digests under that
reference -- never checked against the CNF's own equality variables alone.

Full 80-round work is out of scope: `steps` is a required parameter and these
tests exercise only tiny step counts.
"""

from __future__ import annotations

import pytest

from keylab.hashes.reduced import ripemd160_reduced
from keylab.hashes.ripemd_cnf import ripemd160_collision_cnf
from keylab.sat.solver import find_solver, run_solver


def test_collision_requires_explicit_steps() -> None:
    # steps is required and range-checked; never silently defaulted to full.
    with pytest.raises(ValueError, match="steps is required"):
        ripemd160_collision_cnf(message_length=8, steps=0)
    with pytest.raises(ValueError, match="steps is required"):
        ripemd160_collision_cnf(message_length=8, steps=81)


def test_collision_rejects_bad_message_length() -> None:
    with pytest.raises(ValueError, match="message_length"):
        ripemd160_collision_cnf(message_length=0, steps=2)
    with pytest.raises(ValueError, match="message_length"):
        ripemd160_collision_cnf(message_length=56, steps=2)


def test_collision_rejects_bad_difference() -> None:
    with pytest.raises(ValueError, match="difference"):
        ripemd160_collision_cnf(message_length=8, steps=2, difference=b"\x00" * 8)  # all-zero
    with pytest.raises(ValueError, match="difference"):
        ripemd160_collision_cnf(message_length=8, steps=2, difference=b"\x01" * 4)  # wrong length


def test_collision_model_is_well_formed() -> None:
    model = ripemd160_collision_cnf(message_length=24, steps=2)
    assert model.steps == 2 and model.message_length == 24
    assert len(model.input_bits_a) == len(model.input_bits_b) == 24 * 8
    assert model.clause_count > 0 and model.variable_count > 0
    assert "p cnf" in model.to_dimacs()


def test_collision_solution_verified_against_reference() -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    steps, length = 2, 24
    model = ripemd160_collision_cnf(message_length=length, steps=steps)
    result = run_solver(solver, model.to_dimacs(), timeout=60)
    assert result.status == "SATISFIABLE"

    msg_a, msg_b = model.recover_messages(result.assignments)
    assert msg_a != msg_b, "messages must actually differ (non-trivial collision)"
    # independent check: recompute the reduced-round digest from scratch
    assert ripemd160_reduced(msg_a, steps=steps) == ripemd160_reduced(msg_b, steps=steps)


def test_collision_with_message_difference_characteristic() -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    # a fixed message-level differential: flip one bit in an unused-at-step-2 word.
    steps, length = 2, 24
    difference = bytearray(length)
    difference[8] = 0x01  # byte in word 2 (bytes 8..11), unused by the first 2 rounds
    model = ripemd160_collision_cnf(message_length=length, steps=steps, difference=bytes(difference))
    result = run_solver(solver, model.to_dimacs(), timeout=60)
    assert result.status == "SATISFIABLE"

    msg_a, msg_b = model.recover_messages(result.assignments)
    assert msg_a != msg_b
    # b must equal a XOR difference, and the reduced digests must collide (independent ref)
    assert bytes(x ^ y for x, y in zip(msg_a, msg_b)) == bytes(difference)
    assert ripemd160_reduced(msg_a, steps=steps) == ripemd160_reduced(msg_b, steps=steps)
