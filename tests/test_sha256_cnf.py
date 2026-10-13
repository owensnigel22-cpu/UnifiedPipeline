import csv
import itertools
import json
from io import StringIO

import pytest

from keylab.cli import main
from keylab.hashes.reduced import _SHA_IV, _sha_compress, sha256_reduced
from keylab.hashes.sha256_cnf import (
    SHA256PreimageModel,
    sha256_55byte_preimage_cnf,
    sha256_compression_cnf,
    sha256_hash_preimage_cnf,
    sha256_secret_prefix_cnf,
)
from keylab.sat.cnf import CNF
from keylab.sat.parallel import ParallelCubeResult
from keylab.sat.solver import find_solver, run_solver


def test_sha256_hash_model_builds_dimacs_and_streams_identically() -> None:
    model = sha256_hash_preimage_cnf(bytes(32), message_length=55)
    dimacs = model.to_dimacs()
    streamed = StringIO()
    model.write_dimacs(streamed)

    assert len(model.input_bits) == 55 * 8
    assert dimacs == streamed.getvalue()
    assert dimacs.startswith(f"p cnf {model.formula.variable_count} {len(model.formula.clauses)}\n")
    assert all(clause for clause in model.formula.clauses)
    assert all(
        literal != 0 and abs(literal) <= model.formula.variable_count
        for clause in model.formula.clauses
        for literal in clause
    )


def test_sha256_55byte_compatibility_wrapper() -> None:
    model = sha256_55byte_preimage_cnf(bytes(32))
    assert isinstance(model, SHA256PreimageModel)
    assert len(model.message_bits) == len(model.input_bits) == 440


def test_sha256_models_validate_target_rounds_and_message_length() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        sha256_hash_preimage_cnf(bytes(31), message_length=4)
    with pytest.raises(ValueError, match="between 1 and 64"):
        sha256_hash_preimage_cnf(bytes(32), message_length=4, rounds=0)
    with pytest.raises(ValueError, match="message_length must fit"):
        sha256_hash_preimage_cnf(bytes(32), message_length=-1)


def test_sha256_cnf_cli_dispatches_parallel_input_cubes(monkeypatch, tmp_path, capsys) -> None:
    message = b"\xA5"
    target = sha256_reduced(message, rounds=1)
    model = sha256_hash_preimage_cnf(target, message_length=1, rounds=1)
    assignments = {
        variable: bool((message[index // 8] >> (7 - index % 8)) & 1)
        for index, variable in enumerate(model.input_bits)
    }
    observed: dict[str, object] = {}

    def fake_parallel_solver(
        executable: str,
        dimacs: str,
        variables: tuple[int, ...],
        *,
        depth: int,
        workers: int,
        timeout: float,
    ) -> ParallelCubeResult:
        observed.update(
            executable=executable,
            dimacs=dimacs,
            variables=variables,
            depth=depth,
            workers=workers,
            timeout=timeout,
        )
        return ParallelCubeResult(
            "SATISFIABLE",
            16,
            1,
            depth,
            assignments,
            (),
        )

    monkeypatch.setattr("keylab.cli._solver_version", lambda _solver: "test solver")
    monkeypatch.setattr("keylab.cli.solve_parallel_cubes", fake_parallel_solver)

    assert main(
        [
            "sha256-cnf",
            "--mode",
            "hash",
            "--target",
            target.hex(),
            "--rounds",
            "1",
            "--message-length",
            "1",
            "--output",
            str(tmp_path / "model.cnf"),
            "--solver",
            "test-solver",
            "--cube-depth",
            "4",
            "--parallel-workers",
            "2",
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert observed["depth"] == 4
    assert observed["workers"] == 2
    assert metrics["cube_total"] == 16
    assert metrics["cube_completed"] == 1
    assert metrics["solver_status"] == "SATISFIABLE"
    assert metrics["candidate_validated"] is True
    assert metrics["candidate_hex"] == message.hex()


def test_sha256_cnf_tracks_and_exports_equation_dag(tmp_path, capsys) -> None:
    dag_path = tmp_path / "sha256-circuit.json"
    assert main(
        [
            "sha256-cnf",
            "--mode",
            "hash",
            "--target",
            bytes(32).hex(),
            "--rounds",
            "1",
            "--message-length",
            "1",
            "--output",
            str(tmp_path / "model.cnf"),
            "--dag-output",
            str(dag_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    assert metrics["dag_tracked"] is True
    assert metrics["dag_nodes"] == len(dag["nodes"])
    assert dag["schema"] == "keylab-equation-dag-v1"
    assert (tmp_path / "model.cnf").is_file()


def test_compression_model_accepts_explicit_initial_and_target_states() -> None:
    block = bytes(range(64))
    target_words = _sha_compress(block, _SHA_IV, rounds=4)
    target = b"".join(word.to_bytes(4, "big") for word in target_words)
    model = sha256_compression_cnf(target, rounds=4)

    assert model.mode == "compression"
    assert model.message_length is None
    assert len(model.input_bits) == 512
    assert model.rounds == 4


def test_secret_prefix_model_fixes_known_message_and_recovers_secret() -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    secret, known_message = b"\xA7", b"tag"
    target = sha256_reduced(secret + known_message, rounds=2)
    model = sha256_secret_prefix_cnf(
        target,
        known_message=known_message,
        secret_length=len(secret),
        rounds=2,
    )

    result = run_solver(solver, model.to_dimacs(), timeout=30)

    assert result.status == "SATISFIABLE"
    recovered = model.recover_secret(result.assignments)
    assert recovered == secret
    assert sha256_reduced(recovered + known_message, rounds=2) == target
    assert len(model.fixed_bits) == len(known_message) * 8


def test_secret_prefix_model_can_track_its_equation_dag() -> None:
    target = sha256_reduced(b"s" + b"m", rounds=1)
    model = sha256_secret_prefix_cnf(
        target,
        known_message=b"m",
        secret_length=1,
        rounds=1,
        track_dag=True,
    )

    assert model.model.formula.dag is not None
    model.model.formula.dag.validate()
    assert len(model.model.formula.dag.nodes) > len(model.model.input_bits)


def test_secret_prefix_model_rejects_negative_secret_length() -> None:
    with pytest.raises(ValueError, match="secret_length must be a nonnegative"):
        sha256_secret_prefix_cnf(bytes(32), known_message=b"m", secret_length=-1)


def test_secret_prefix_recovery_rejects_inconsistent_solver_assignment() -> None:
    model = sha256_secret_prefix_cnf(
        bytes(32),
        known_message=b"m",
        secret_length=1,
        rounds=1,
    )
    assignments = {
        abs(literal): not bool((ord("m") >> (7 - bit_index)) & 1)
        for bit_index, literal in enumerate(model.model.input_bits[8:])
    }
    with pytest.raises(ValueError, match="does not match the fixed known message"):
        model.recover_secret(assignments)


def test_secret_prefix_cli_generates_dimacs_and_metrics(tmp_path, capsys) -> None:
    secret, known_message = b"\xA7", b"tag"
    target = sha256_reduced(secret + known_message, rounds=2)
    output_path = tmp_path / "prefix.cnf"

    assert main(
        [
            "sha256-prefix-cnf",
            "--target",
            target.hex(),
            "--message",
            known_message.hex(),
            "--secret-length",
            str(len(secret)),
            "--rounds",
            "2",
            "--output",
            str(output_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["mode"] == "secret-prefix-hash"
    assert metrics["rounds"] == 2
    assert metrics["secret_length"] == len(secret)
    assert metrics["fixed_input_bits"] == len(known_message) * 8
    assert "use HMAC-SHA-256" in metrics["warning"]
    assert output_path.read_text(encoding="ascii").startswith("p cnf ")


def test_secret_prefix_cli_solves_and_verifies_candidate(capsys) -> None:
    solver = find_solver(("cryptominisat5",))
    if solver is None:
        pytest.skip("CryptoMiniSat is not installed")
    secret, known_message = b"\xA7", b"tag"
    target = sha256_reduced(secret + known_message, rounds=2)

    assert main(
        [
            "sha256-prefix-cnf",
            "--target",
            target.hex(),
            "--message",
            known_message.hex(),
            "--secret-length",
            str(len(secret)),
            "--rounds",
            "2",
            "--solver",
            solver,
            "--timeout",
            "30",
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["solver_status"] == "SATISFIABLE"
    assert metrics["candidate_validated"] is True
    assert metrics["candidate_secret_hex"] == secret.hex()


def test_fixed_input_bits_validate_atomically() -> None:
    model = sha256_hash_preimage_cnf(bytes(32), message_length=2, rounds=1)
    with pytest.raises(ValueError, match="input bit index"):
        model.constrain_input_bits({0: 1, 16: 0})
    assert model.fixed_bits == {}

    model.constrain_input_bits({0: 1})
    original_clause_count = model.clause_count
    with pytest.raises(ValueError, match="already fixed"):
        model.constrain_input_bits({0: 0, 1: 1})
    assert model.fixed_bits == {0: 1}
    assert model.clause_count == original_clause_count


def test_modular_adder_omits_unused_most_significant_carry_gate() -> None:
    cnf = CNF()
    false_literal = cnf.fresh_var()
    left = tuple(cnf.fresh_var() for _ in range(8))
    right = tuple(cnf.fresh_var() for _ in range(8))

    result = cnf.add_many((left, right), 8, -false_literal)

    assert len(result) == 8
    assert sum(key[0] == "maj3" for key in cnf._memo) == 7
    assert cnf.variable_count == 40
    assert len(cnf.clauses) == 106


def test_cnf_gates_fold_constants_and_repeated_literals() -> None:
    cnf = CNF()
    true_literal = cnf.constant(True)
    false_literal = -true_literal
    variable = cnf.input_var()
    initial_variables = cnf.variable_count

    assert cnf.and_gate(variable, true_literal) == variable
    assert cnf.and_gate(variable, false_literal) == false_literal
    assert cnf.or_gate(variable, false_literal) == variable
    assert cnf.or_gate(variable, true_literal) == true_literal
    assert cnf.xor(variable, false_literal) == variable
    assert cnf.xor(variable, true_literal) == -variable
    assert cnf.xor(variable, variable) == false_literal
    assert cnf.xor(variable, -variable) == true_literal
    assert cnf.majority(variable, variable, -variable) == variable
    assert cnf.majority(variable, -variable, true_literal) == true_literal
    assert cnf.mux(true_literal, variable, -variable) == variable
    assert cnf.mux(variable, true_literal, false_literal) == variable

    assert cnf.variable_count == initial_variables


@pytest.mark.parametrize("literals", [(1, 2, 3), (-1, 2, -3)])
def test_direct_xor3_encoding_matches_truth_table(literals: tuple[int, int, int]) -> None:
    cnf = CNF()
    inputs = tuple(cnf.fresh_var() for _ in range(3))
    output = cnf.xor3(*literals)

    for values in itertools.product((False, True), repeat=3):
        assignments = dict(zip(inputs, values))
        literal_values = tuple(
            assignments[abs(literal)] == (literal > 0) for literal in literals
        )
        expected = literal_values[0] ^ literal_values[1] ^ literal_values[2]
        satisfying = {**assignments, output: expected}
        assert all(
            any(satisfying[abs(literal)] == (literal > 0) for literal in clause)
            for clause in cnf.clauses
        )
        satisfying[output] = not expected
        assert not all(
            any(satisfying[abs(literal)] == (literal > 0) for literal in clause)
            for clause in cnf.clauses
        )


def test_xor_gates_memoize_complemented_input_forms() -> None:
    cnf = CNF()
    first, second, third = (cnf.fresh_var() for _ in range(3))

    xor2 = cnf.xor(first, second)
    xor3 = cnf.xor3(first, second, third)
    variable_count = cnf.variable_count
    clause_count = len(cnf.clauses)

    assert cnf.xor(-first, second) == -xor2
    assert cnf.xor(first, -second) == -xor2
    assert cnf.xor(-first, -second) == xor2
    assert cnf.xor3(-first, second, third) == -xor3
    assert cnf.xor3(first, -second, third) == -xor3
    assert cnf.xor3(first, second, -third) == -xor3
    assert cnf.xor3(-first, -second, third) == xor3
    assert cnf.xor3(third, first, second) == xor3
    assert cnf.variable_count == variable_count
    assert len(cnf.clauses) == clause_count


@pytest.mark.parametrize(
    "operands",
    [
        ((), 0),
        ((1,), 1),
        ((0xFF, 1, 3), 3),
        ((0xFF, 0x02, 0xFE, 0x03), 0x02),
        ((0x81, 0x7F, 0xFF, 0x01, 0xFE), 0xFE),
    ],
)
def test_carry_save_adder_matches_modular_sum_with_solver(
    operands: tuple[tuple[int, ...], int],
) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    values, expected = operands
    cnf = CNF()
    true_literal = cnf.fresh_var()
    cnf.add_clause(true_literal)
    false_literal = -true_literal
    input_words: list[tuple[int, ...]] = []
    for value in values:
        bits = tuple(cnf.fresh_var() for _ in range(8))
        for bit, variable in enumerate(bits):
            cnf.add_clause(variable if value & (1 << bit) else -variable)
        input_words.append(bits)

    output = cnf.add_many(input_words, 8, false_literal)
    for bit, literal in enumerate(output):
        cnf.add_clause(literal if expected & (1 << bit) else -literal)

    assert run_solver(solver, cnf.to_dimacs(), timeout=10).status == "SATISFIABLE"


def test_cryptominisat_file_input_dispatch() -> None:
    solver = find_solver(("cryptominisat5",))
    if solver is None:
        pytest.skip("CryptoMiniSat is not installed")

    result = run_solver(solver, "p cnf 1 1\n1 0\n", timeout=10)

    assert result.status == "SATISFIABLE"
    assert result.assignments[1] is True


@pytest.mark.parametrize("mode,rounds", [("hash", 1), ("hash", 16), ("hash", 17), ("compression", 8)])
def test_known_reduced_round_input_satisfies_sat_model(mode: str, rounds: int) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    if mode == "hash":
        known_input = b"SAT!"
        target = sha256_reduced(known_input, rounds)
        model = sha256_hash_preimage_cnf(target, message_length=len(known_input), rounds=rounds)
    else:
        known_input = bytes(range(64))
        target_words = _sha_compress(known_input, _SHA_IV, rounds)
        target = b"".join(word.to_bytes(4, "big") for word in target_words)
        model = sha256_compression_cnf(target, rounds=rounds)

    model.constrain_input_bits(
        {
            byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
            for byte_index, byte in enumerate(known_input)
            for bit_index in range(8)
        }
    )
    result = run_solver(solver, model.to_dimacs(), timeout=30)

    assert result.status == "SATISFIABLE"
    assert model.recover_input(result.assignments) == known_input


@pytest.mark.parametrize("message_length", [56, 64, 120])
def test_multiblock_hash_model_matches_known_reduced_round_input(message_length: int) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    known_input = bytes(index % 256 for index in range(message_length))
    rounds = 2
    target = sha256_reduced(known_input, rounds)
    model = sha256_hash_preimage_cnf(target, message_length=message_length, rounds=rounds)
    model.constrain_input_bits(
        {
            byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
            for byte_index, byte in enumerate(known_input)
            for bit_index in range(8)
        }
    )

    result = run_solver(solver, model.to_dimacs(), timeout=30)

    assert result.status == "SATISFIABLE"
    assert model.recover_input(result.assignments) == known_input


def test_cli_records_generation_metrics(tmp_path, capsys) -> None:
    output_path = tmp_path / "experiment.cnf"

    assert main(
        [
            "sha256-cnf",
            "--mode",
            "hash",
            "--target",
            bytes(32).hex(),
            "--message-length",
            "1",
            "--rounds",
            "1",
            "--fix-bit",
            "0=1",
            "--output",
            str(output_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["mode"] == "hash"
    assert metrics["rounds"] == 1
    assert metrics["fixed_input_bits"] == 1
    assert metrics["generation_seconds"] >= 0
    assert metrics["variables"] > 0
    assert metrics["clauses"] > 0
    assert output_path.read_text(encoding="ascii").startswith("p cnf ")


def test_cli_records_external_solver_metrics(tmp_path, capsys) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    message = b"A"
    target = sha256_reduced(message, rounds=1)
    output_path = tmp_path / "solved.cnf"
    fixed = [f"{bit}=1" if message[0] & (1 << (7 - bit)) else f"{bit}=0" for bit in range(8)]
    arguments = [
        "sha256-cnf",
        "--mode",
        "hash",
        "--target",
        target.hex(),
        "--message-length",
        "1",
        "--rounds",
        "1",
        "--output",
        str(output_path),
        "--solver",
        solver,
        "--timeout",
        "30",
    ]
    for constraint in fixed:
        arguments.extend(("--fix-bit", constraint))

    assert main(arguments) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["solver"] == solver
    assert metrics["solver_version"]
    assert metrics["solver_timeout_seconds"] == 30
    assert metrics["solver_seconds"] >= 0
    assert metrics["solver_status"] == "SATISFIABLE"
    assert metrics["candidate_validated"] is True
    assert metrics["candidate_hex"] == message.hex()


def test_sha256_cnf_benchmark_reports_known_input_encoding_metrics(capsys) -> None:
    solver = find_solver()
    arguments = [
        "sha256-cnf-benchmark",
        "--start-round",
        "16",
        "--end-round",
        "17",
        "--timeout",
        "30",
    ]
    if solver is not None:
        arguments.extend(("--solver", solver))

    assert main(arguments) == 0

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(row["rounds"], row["xor3_encoding"]) for row in rows] == [
        (16, "direct"),
        (16, "chain"),
        (17, "direct"),
        (17, "chain"),
    ]
    assert all(row["benchmark"] == "sha256-cnf-known-input" for row in rows)
    assert [row["schedule_expansion_words_per_block"] for row in rows] == [0, 0, 1, 1]
    assert all(row["fixed_input_bits"] == len(b"keylab benchmark input") * 8 for row in rows)
    assert all(row["variables"] > 0 and row["clauses"] > 0 for row in rows)
    assert all(row["input_constraint_seconds"] >= 0 for row in rows)
    assert all(row["dimacs_bytes"] > 0 for row in rows)
    assert all(row["dimacs_serialization_seconds"] >= 0 for row in rows)
    if solver is not None:
        assert all(row["solver_seconds"] >= 0 for row in rows)
        assert all(row["solver_status"] == "SATISFIABLE" for row in rows)
        assert all(row["candidate_validated"] for row in rows)


def test_sha256_cnf_benchmark_defaults_to_pre_expansion_range(capsys) -> None:
    assert main(["sha256-cnf-benchmark"]) == 0

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(row["rounds"], row["xor3_encoding"]) for row in rows] == [
        (rounds, encoding)
        for rounds in (14, 15, 16)
        for encoding in ("direct", "chain")
    ]
    assert [row["schedule_expansion_words_per_block"] for row in rows] == [0] * 6


def test_sha256_cnf_benchmark_exports_csv_and_compares_solvers(tmp_path, capsys) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    csv_path = tmp_path / "sha256-benchmark.csv"

    assert main(
        [
            "sha256-cnf-benchmark",
            "--start-round",
            "1",
            "--end-round",
            "1",
            "--solver",
            solver,
            "--solver",
            solver,
            "--csv-output",
            str(csv_path),
        ]
    ) == 0

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 4
    assert [row["solver"] for row in rows] == [solver] * 4
    assert [row["xor3_encoding"] for row in rows] == [
        "direct",
        "direct",
        "chain",
        "chain",
    ]
    assert all(row["solver_status"] == "SATISFIABLE" for row in rows)
    with csv_path.open(encoding="utf-8", newline="") as csv_file:
        csv_rows = list(csv.DictReader(csv_file))
    assert len(csv_rows) == 4
    assert all(row["hash"] == "sha256" for row in csv_rows)
    assert all(row["solver_status"] == "SATISFIABLE" for row in csv_rows)


def test_sha256_cnf_chain_encoding_matches_direct_formula_metrics() -> None:
    message = b"XOR3"
    target = sha256_reduced(message, rounds=2)
    direct = sha256_hash_preimage_cnf(
        target,
        message_length=len(message),
        rounds=2,
        xor3_encoding="direct",
    )
    chain = sha256_hash_preimage_cnf(
        target,
        message_length=len(message),
        rounds=2,
        xor3_encoding="chain",
    )

    assert direct.variable_count < chain.variable_count
    assert direct.clause_count >= chain.clause_count


def test_fixed_sha256_input_bits_are_propagated_during_model_construction() -> None:
    message = b"fixed"
    target = sha256_reduced(message, rounds=4)
    assignments = {
        byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
        for byte_index, byte in enumerate(message)
        for bit_index in range(8)
    }

    symbolic = sha256_hash_preimage_cnf(
        target,
        message_length=len(message),
        rounds=4,
    )
    fixed = sha256_hash_preimage_cnf(
        target,
        message_length=len(message),
        rounds=4,
        fixed_bits=assignments,
    )

    assert fixed.fixed_bits == assignments
    assert fixed.variable_count < symbolic.variable_count
    assert fixed.clause_count < symbolic.clause_count
    assert fixed.variable_count < symbolic.variable_count // 10
    assert fixed.clause_count < symbolic.clause_count // 10


def test_sha256_cnf_benchmark_rejects_invalid_round_range() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["sha256-cnf-benchmark", "--start-round", "18", "--end-round", "14"])
    assert exc_info.value.code == 2


def test_hash_cnf_selftest_checks_sha_schedule_transition(capsys) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    assert main(
        [
            "hash-cnf-selftest",
            "--hash",
            "sha256",
            "--rounds",
            "16",
            "17",
            "--solver",
            solver,
        ]
    ) == 0

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["rounds"] for row in rows] == [16, 17]
    assert all(row["solver_status"] == "SATISFIABLE" for row in rows)
    assert all(row["candidate_validated"] is True for row in rows)


def test_hash_cnf_selftest_reports_when_solver_is_missing(monkeypatch, capsys) -> None:
    from keylab import cli

    monkeypatch.setattr(cli, "find_solver", lambda: None)

    assert main(["hash-cnf-selftest", "--hash", "sha256", "--rounds", "1"]) == 0

    row = json.loads(capsys.readouterr().out)
    assert row["status"] == "CNF_GENERATED_SOLVER_NOT_FOUND"
    assert "candidate_validated" not in row
