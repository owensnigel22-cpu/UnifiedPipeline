"""MILP emitter for the reduced-round compression: correct model, clean emission.

Emission is pure-Python and always available; solving needs the ``milp`` extra
(``pulp``) and is skipped when it is absent.
"""

from __future__ import annotations

import secrets

import pytest

from keylab.hashes.reduced import _SHA_IV, _sha_compress
from keylab.research.sha256_prob import compression_milp
from keylab.research.sha256_prob.sha256_milp import Constraint


def _full_wire_values(circuit, assignment: dict[int, int]) -> list[int]:
    value = [0] * circuit.num_vars
    for kind, out, data in circuit.gates:
        if kind == "const":
            value[out] = data[0]
        elif kind == "input":
            value[out] = assignment.get(out, 0) & 1
        elif kind == "xor":
            acc = 0
            for src in data:
                acc ^= value[src]
            value[out] = acc
        elif kind == "maj":
            a, b, c = (value[s] for s in data)
            value[out] = 1 if (a + b + c) >= 2 else 0
        elif kind == "ch":
            e, f, g = (value[s] for s in data)
            value[out] = f if e else g
    return value


def _check_model_admits_true_assignment(model) -> int:
    """Return the number of constraint violations under a real wire assignment."""
    circuit = model.circuit
    block = secrets.token_bytes(64)
    words = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
    assignment = {var: (words[w] >> b) & 1 for (w, b), var in circuit.input_map().items()}
    value = _full_wire_values(circuit, assignment)

    def var_value(name: str) -> int:
        return value[int(name[1:])]

    # Solve each xor slack from its equality row, then check every constraint.
    slack: dict[str, int] = {}
    for constraint in model.constraints:
        lhs = 0
        slack_term = None
        for coeff, name in constraint.terms:
            if name.startswith("s"):
                slack_term = (coeff, name)
            else:
                lhs += coeff * var_value(name)
        if slack_term is not None and constraint.sense == "=":
            coeff, name = slack_term
            raw = (constraint.rhs - lhs) / coeff
            slack[name] = int(raw)
    violations = 0
    for constraint in model.constraints:
        lhs = 0
        for coeff, name in constraint.terms:
            x = slack.get(name, 0) if name.startswith("s") else var_value(name)
            lhs += coeff * x
        if constraint.sense == "=":
            ok = lhs == constraint.rhs
        elif constraint.sense == "<=":
            ok = lhs <= constraint.rhs
        else:
            ok = lhs >= constraint.rhs
        violations += 0 if ok else 1
    return violations


def test_constraint_validates_sense() -> None:
    with pytest.raises(ValueError, match="sense"):
        Constraint("c", ((1, "b0"),), "<", 0)


@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_milp_admits_the_true_wire_assignment(rounds: int) -> None:
    model = compression_milp(rounds, free_input_bits=512)
    assert _check_model_admits_true_assignment(model) == 0


def test_lp_emission_is_well_formed(tmp_path) -> None:
    model = compression_milp(1, free_input_bits=32)
    text = model.to_lp()
    assert text.startswith("\\ KeyLab")
    assert "Minimize" in text and "Subject To" in text and "Binaries" in text
    assert text.rstrip().endswith("End")
    path = model.write_lp(tmp_path / "model.lp")
    assert path.read_text(encoding="ascii") == text


def test_mps_emission_is_well_formed(tmp_path) -> None:
    model = compression_milp(1, free_input_bits=32)
    text = model.to_mps()
    assert text.startswith("NAME")
    assert "ROWS" in text and "COLUMNS" in text and "BOUNDS" in text
    assert "INTORG" in text and "INTEND" in text
    assert text.rstrip().endswith("ENDATA")
    path = model.write_mps(tmp_path / "model.mps")
    assert path.read_text(encoding="ascii") == text


def test_target_conditioning_pins_output_bits() -> None:
    digest = bytes(range(32))
    model = compression_milp(1, free_input_bits=64, target=digest, target_bits=8)
    assert len(model.conditioned) == 8
    pin_rows = [c for c in model.constraints if c.name.startswith("t")]
    assert len(pin_rows) == 8
    for row in pin_rows:
        assert row.sense == "=" and row.rhs in (0, 1)


def test_compression_milp_validates_arguments() -> None:
    with pytest.raises(ValueError, match="target_bits"):
        compression_milp(1, target_bits=257)
    with pytest.raises(ValueError, match="32-byte"):
        compression_milp(1, target_bits=8, target=None)


@pytest.mark.slow
def test_milp_solve_finds_a_verified_preimage() -> None:
    pytest.importorskip("pulp")
    # Pin the low 8 output bits of a real 1-round digest; the solver must return a
    # forward-verified preimage block.
    message = bytearray(64)
    message[0:4] = b"\x01\x23\x45\x67"
    target = b"".join(w.to_bytes(4, "big") for w in _sha_compress(bytes(message), _SHA_IV, 1))
    model = compression_milp(1, free_input_bits=64, target=target, target_bits=8)
    result = model.solve()
    assert result.feasible is True
    assert result.verified is True
    assert result.block is not None and len(result.block) == 64
