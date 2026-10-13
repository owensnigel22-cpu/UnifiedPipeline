import json
from io import StringIO

import pytest

from keylab.cli import main
from keylab.hashes.reduced import ripemd160, ripemd160_matches_hashlib, ripemd160_reduced
from keylab.hashes.ripemd_cnf import ripemd160_preimage_cnf
from keylab.sat.solver import find_solver, run_solver


def _known_bit_constraints(message: bytes) -> dict[int, int]:
    return {
        byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
        for byte_index, byte in enumerate(message)
        for bit_index in range(8)
    }


def test_ripemd160_reduced_reference_preserves_standard_digest() -> None:
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert ripemd160_reduced(b"abc", steps=80) == ripemd160(b"abc")
    assert ripemd160_matches_hashlib(b"abc")


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (
            b"message digest",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        ),
    ],
)
def test_ripemd160_matches_published_reference_vectors(message: bytes, expected: str) -> None:
    assert ripemd160(message).hex() == expected


@pytest.mark.parametrize("steps", [1, 16, 17, 32, 48, 64, 80])
def test_known_reduced_round_message_satisfies_ripemd_sat_model(steps: int) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    message = b"abc"
    target = ripemd160_reduced(message, steps=steps)
    model = ripemd160_preimage_cnf(target, message_length=len(message), steps=steps)
    model.constrain_input_bits(_known_bit_constraints(message))

    result = run_solver(solver, model.to_dimacs(), timeout=60)

    assert result.status == "SATISFIABLE"
    recovered = model.recover_input(result.assignments)
    assert recovered == message
    assert ripemd160_reduced(recovered, steps=steps) == target


def test_ripemd_model_serializes_dimacs_and_validates_input_constraints() -> None:
    model = ripemd160_preimage_cnf(bytes(20), message_length=2, steps=1)
    serialized = StringIO()
    model.write_dimacs(serialized)

    assert serialized.getvalue() == model.to_dimacs()
    assert len(model.input_bits) == 16
    with pytest.raises(ValueError, match="input bit index"):
        model.constrain_input_bits({0: 1, 16: 0})
    assert model.fixed_bits == {}


@pytest.mark.parametrize(
    ("target", "message_length", "steps", "message"),
    [
        (bytes(19), 1, 1, "target"),
        (bytes(20), 56, 1, "message_length"),
        (bytes(20), 1, 0, "steps"),
    ],
)
def test_ripemd_model_rejects_invalid_parameters(
    target: bytes, message_length: int, steps: int, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        ripemd160_preimage_cnf(target, message_length=message_length, steps=steps)


def test_ripemd160_cnf_cli_writes_model_and_metrics(tmp_path, capsys) -> None:
    output_path = tmp_path / "ripemd.cnf"
    target = ripemd160_reduced(b"A", steps=1)

    assert main(
        [
            "ripemd160-cnf",
            "--target",
            target.hex(),
            "--message-length",
            "1",
            "--steps",
            "1",
            "--fix-bit",
            "0=0",
            "--output",
            str(output_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["mode"] == "hash-preimage"
    assert metrics["steps"] == 1
    assert metrics["fixed_input_bits"] == 1
    assert output_path.read_text(encoding="ascii").startswith("p cnf ")


def test_hash_cnf_selftest_checks_ripemd160_known_input(capsys) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    assert main(
        [
            "hash-cnf-selftest",
            "--hash",
            "ripemd160",
            "--rounds",
            "16",
            "--solver",
            solver,
        ]
    ) == 0

    row = json.loads(capsys.readouterr().out)
    assert row["solver_status"] == "SATISFIABLE"
    assert row["candidate_validated"] is True
