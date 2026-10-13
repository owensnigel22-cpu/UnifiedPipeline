from itertools import product

import pytest

from keylab.sat.cnf import CNF
from keylab.sat.dag import EquationDAG, Op, Tri


def test_dag_rejects_duplicate_inputs_and_forward_references() -> None:
    dag = EquationDAG()
    dag.add_input(1, "x")
    with pytest.raises(ValueError, match="already defined"):
        dag.add_input(1, "duplicate")
    with pytest.raises(ValueError, match="previously defined"):
        dag.add_gate(Op.NOT, (1,))


def test_dag_validates_topology_and_serializes_stably() -> None:
    dag = EquationDAG()
    input_node = dag.add_input(1, "x")
    output_node = dag.add_gate(Op.NOT, (input_node,), variable=2, label="not_x")

    dag.validate()

    assert dag.nodes[output_node].inputs == (input_node,)
    assert dag.to_dict()["nodes"][-1] == {
        "id": 1,
        "op": "not",
        "inputs": [0],
        "variable": 2,
        "value": None,
        "label": "not_x",
    }


@pytest.mark.parametrize(
    ("op", "inputs", "expected"),
    [
        (Op.AND, (True, None), None),
        (Op.AND, (False, None), False),
        (Op.OR, (True, None), True),
        (Op.XOR, (False, None), None),
        (Op.XOR3, (True, False, None), None),
        (Op.XOR3, (True, True, False), False),
        (Op.MAJ3, (True, True, None), True),
        (Op.MAJ3, (True, False, None), None),
        (Op.MUX, (None, True, True), True),
        (Op.MUX, (None, True, False), None),
    ],
)
def test_dag_three_valued_gate_evaluation(
    op: Op,
    inputs: tuple[bool | None, ...],
    expected: bool | None,
) -> None:
    dag = EquationDAG()
    assignment: dict[int, bool | Tri] = {}
    parents = []
    for variable, value in enumerate(inputs, 1):
        parents.append(dag.add_input(variable))
        if value is not None:
            assignment[variable] = value
    result_node = dag.add_gate(op, tuple(parents), variable=len(inputs) + 1)

    result = dag.evaluate(assignment)[result_node]

    expected_tri = Tri.UNKNOWN if expected is None else Tri.from_bool(expected)
    assert result is expected_tri


def test_cnf_tracking_dag_matches_gate_outputs_and_clauses() -> None:
    formula = CNF(track_dag=True)
    assert formula.dag is not None
    true_variable = formula.constant(True, "true")
    left = formula.input_var("left")
    right = formula.input_var("right")
    third = formula.input_var("third")
    gates = (
        formula.and_gate(left, right),
        formula.or_gate(-left, third),
        formula.xor(left, right),
        formula.xor3(left, right, third),
        formula.majority(left, right, third),
        formula.mux(left, right, third),
    )
    formula.dag.validate()

    for values in product((False, True), repeat=3):
        input_assignment = dict(zip((left, right, third), values))
        evaluated = formula.dag.evaluate(input_assignment)
        by_variable = formula.dag.variable_values(evaluated)
        assignment = {variable: value.as_bool() for variable, value in by_variable.items()}
        assert assignment[true_variable] is True

        assert all(
            any(assignment[abs(literal)] == (literal > 0) for literal in clause)
            for clause in formula.clauses
        )
        assert tuple(by_variable[gate] is Tri.TRUE for gate in gates) == (
            values[0] and values[1],
            (not values[0]) or values[2],
            values[0] != values[1],
            values[0] ^ values[1] ^ values[2],
            sum(values) >= 2,
            values[1] if values[0] else values[2],
        )


def test_cnf_without_tracking_preserves_default_behavior() -> None:
    formula = CNF()
    left, right = formula.fresh_var(), formula.fresh_var()
    formula.xor(left, right)
    assert formula.dag is None
