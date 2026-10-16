import itertools
import json

import pytest

from keylab.cli import main
from keylab.sat.anf import MQCNFEncoder
from keylab.sat.solver import find_solver, run_solver


def test_mq_encoder_shares_products_and_reduces_boolean_diagonals() -> None:
    encoder = MQCNFEncoder(3)
    encoder.add_equation([(1, 2)], [3], 1)
    encoder.add_equation([(2, 1), (1, 1)], [1, 3], 0)

    assert encoder.product_variables == {(1, 2): 4}
    assert encoder.equation_count == 2
    assert encoder.formula.variable_count == 5


def test_mq_encoder_cancels_duplicate_terms_over_gf2() -> None:
    encoder = MQCNFEncoder(2)
    encoder.add_equation([(1, 2), (2, 1)], [1, 1], 0)

    assert encoder.product_variables == {}
    assert encoder.formula.clauses == []
    assert encoder.equation_count == 1


@pytest.mark.parametrize("rhs", [0, 1])
def test_mq_encoder_constant_equation(rhs: int) -> None:
    encoder = MQCNFEncoder(0)
    encoder.add_equation([], [], rhs)

    assert encoder.formula.clauses == ([] if rhs == 0 else [()])


@pytest.mark.parametrize(
    ("quadratic_terms", "linear_terms", "rhs"),
    [
        ([(0, 1)], [], 0),
        ([(1, 3)], [], 0),
        ([], [1.5], 0),
        ([], [], 2),
    ],
)
def test_mq_encoder_rejects_invalid_equations(
    quadratic_terms: list[tuple[int, int]], linear_terms: list[int], rhs: int
) -> None:
    encoder = MQCNFEncoder(2)
    with pytest.raises(ValueError):
        encoder.add_equation(quadratic_terms, linear_terms, rhs)

    assert encoder.equation_count == 0
    assert encoder.product_variables == {}


def test_mq_encoder_cnf_matches_equation_truth_table() -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    for values in itertools.product((0, 1), repeat=4):
        encoder = MQCNFEncoder(4)
        encoder.add_equation([(1, 2)], [3, 4], 1)
        for variable, value in enumerate(values, start=1):
            encoder.formula.add_clause(variable if value else -variable)

        expected = (values[0] & values[1]) ^ values[2] ^ values[3] == 1
        result = run_solver(solver, encoder.to_dimacs(), timeout=10)
        assert result.status == ("SATISFIABLE" if expected else "UNSATISFIABLE")


def test_mq_cnf_cli_writes_standard_dimacs_and_metrics(tmp_path, capsys) -> None:
    equation_path = tmp_path / "equations.json"
    output_path = tmp_path / "model.cnf"
    equation_path.write_text(
        json.dumps(
            {
                "num_variables": 3,
                "equations": [
                    {
                        "quadratic_terms": [[1, 2]],
                        "linear_terms": [3],
                        "rhs": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "mq-cnf",
            "--equations",
            str(equation_path),
            "--output",
            str(output_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["mode"] == "mq-anf-to-cnf"
    assert metrics["quadratic_products"] == 1
    assert metrics["equations"] == 1
    dimacs = output_path.read_text(encoding="ascii")
    assert dimacs.startswith("p cnf ")
    assert "\nx " not in dimacs


def test_mq_cnf_cli_rejects_malformed_json_schema(tmp_path) -> None:
    equation_path = tmp_path / "bad-equations.json"
    equation_path.write_text('{"num_variables": 1, "equations": [{}]}', encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(["mq-cnf", "--equations", str(equation_path)])

    assert exc_info.value.code == 2

from keylab.sat.cnf import CNF


def test_dimacs_pure_cnf() -> None:
    cnf = CNF()

    a = cnf.fresh_var()
    b = cnf.fresh_var()

    xor_ab = cnf.xor(a, b)

    cnf.add_clause(xor_ab)

    dimacs = cnf.to_dimacs()

    assert dimacs.startswith("p cnf ")
    assert "\nx " not in dimacs