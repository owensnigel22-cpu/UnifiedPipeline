"""Validated Boolean equation DAGs with three-valued evaluation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from itertools import product


class Op(str, Enum):
    """Supported Boolean node operations."""

    INPUT = "input"
    CONST = "const"
    NOT = "not"
    AND = "and"
    OR = "or"
    XOR = "xor"
    XOR3 = "xor3"
    MAJ3 = "maj3"
    MUX = "mux"


class Tri(str, Enum):
    """Three-valued Boolean result."""

    FALSE = "false"
    TRUE = "true"
    UNKNOWN = "unknown"

    @classmethod
    def from_bool(cls, value: bool) -> Tri:
        return cls.TRUE if value else cls.FALSE

    def as_bool(self) -> bool:
        if self is Tri.UNKNOWN:
            raise ValueError("unknown has no Boolean value")
        return self is Tri.TRUE


@dataclass(frozen=True)
class DAGNode:
    """A gate with topologically earlier parent node identifiers."""

    node_id: int
    op: Op
    inputs: tuple[int, ...] = ()
    variable: int | None = None
    value: bool | None = None
    label: str = ""


def _arity(op: Op) -> int | None:
    return {
        Op.NOT: 1,
        Op.AND: 2,
        Op.OR: 2,
        Op.XOR: 2,
        Op.XOR3: 3,
        Op.MAJ3: 3,
        Op.MUX: 3,
    }.get(op)


def _apply(op: Op, values: tuple[bool, ...]) -> bool:
    if op is Op.NOT:
        return not values[0]
    if op is Op.AND:
        return values[0] and values[1]
    if op is Op.OR:
        return values[0] or values[1]
    if op is Op.XOR:
        return values[0] != values[1]
    if op is Op.XOR3:
        return values[0] ^ values[1] ^ values[2]
    if op is Op.MAJ3:
        return sum(values) >= 2
    if op is Op.MUX:
        return values[1] if values[0] else values[2]
    raise ValueError(f"operation {op.value} is not a Boolean gate")


class EquationDAG:
    """A Boolean DAG keyed by DIMACS variables, with strict topology checks."""

    def __init__(self) -> None:
        self.nodes: list[DAGNode] = []
        self.by_var: dict[int, int] = {}
        self._negations: dict[int, int] = {}

    def add_input(self, variable: int, label: str = "") -> int:
        """Add a unique external input variable and return its node identifier."""
        if type(variable) is not int or variable <= 0:
            raise ValueError("input variable must be a positive integer")
        if variable in self.by_var:
            raise ValueError(f"variable {variable} is already defined")
        node_id = len(self.nodes)
        self.nodes.append(DAGNode(node_id, Op.INPUT, variable=variable, label=label))
        self.by_var[variable] = node_id
        return node_id

    def add_constant(self, variable: int, value: bool, label: str = "") -> int:
        """Add a Boolean constant represented by a DIMACS variable."""
        if type(variable) is not int or variable <= 0:
            raise ValueError("constant variable must be a positive integer")
        if type(value) is not bool:
            raise ValueError("constant value must be bool")
        if variable in self.by_var:
            raise ValueError(f"variable {variable} is already defined")
        node_id = len(self.nodes)
        self.nodes.append(
            DAGNode(node_id, Op.CONST, variable=variable, value=value, label=label)
        )
        self.by_var[variable] = node_id
        return node_id

    def add_gate(
        self,
        op: Op,
        inputs: tuple[int, ...],
        *,
        variable: int | None = None,
        label: str = "",
    ) -> int:
        """Add a gate after its inputs, rejecting invalid or forward references."""
        if not isinstance(op, Op) or op in (Op.INPUT, Op.CONST):
            raise ValueError("add_gate requires a Boolean gate operation")
        expected_arity = _arity(op)
        if len(inputs) != expected_arity:
            raise ValueError(f"{op.value} requires exactly {expected_arity} inputs")
        if any(type(parent) is not int or not 0 <= parent < len(self.nodes) for parent in inputs):
            raise ValueError("gate inputs must reference previously defined nodes")
        if variable is not None:
            if type(variable) is not int or variable <= 0:
                raise ValueError("gate variable must be a positive integer")
            if variable in self.by_var:
                raise ValueError(f"variable {variable} is already defined")

        node_id = len(self.nodes)
        self.nodes.append(DAGNode(node_id, op, inputs, variable=variable, label=label))
        if variable is not None:
            self.by_var[variable] = node_id
        return node_id

    def _literal_node(self, literal: int) -> int:
        if type(literal) is not int or literal == 0:
            raise ValueError("DAG literals must be nonzero integers")
        variable = abs(literal)
        parent = self.by_var.get(variable)
        if parent is None:
            parent = self.add_input(variable, label=f"auto[{variable}]")
        if literal > 0:
            return parent
        negation = self._negations.get(parent)
        if negation is None:
            negation = self.add_gate(Op.NOT, (parent,), label=f"not[{variable}]")
            self._negations[parent] = negation
        return negation

    def add_literal_gate(
        self,
        op: Op,
        literals: tuple[int, ...],
        *,
        variable: int,
        label: str = "",
    ) -> int:
        """Add a gate whose inputs are signed DIMACS literals."""
        parents = tuple(self._literal_node(literal) for literal in literals)
        return self.add_gate(op, parents, variable=variable, label=label)

    def validate(self) -> None:
        """Check node order, variable uniqueness, operation arity, and mappings."""
        observed_variables: dict[int, int] = {}
        for expected_id, node in enumerate(self.nodes):
            if node.node_id != expected_id:
                raise ValueError("node identifiers must match topological list order")
            if any(parent < 0 or parent >= node.node_id for parent in node.inputs):
                raise ValueError(f"node {node.node_id} contains a forward or invalid reference")
            if node.op is Op.INPUT:
                if node.inputs or node.variable is None or node.value is not None:
                    raise ValueError(f"input node {node.node_id} has invalid fields")
            elif node.op is Op.CONST:
                if (
                    node.inputs
                    or node.variable is None
                    or type(node.value) is not bool
                ):
                    raise ValueError(f"constant node {node.node_id} has invalid fields")
            elif len(node.inputs) != _arity(node.op):
                raise ValueError(f"gate node {node.node_id} has invalid arity")

            if node.variable is not None:
                if node.variable in observed_variables:
                    raise ValueError(f"variable {node.variable} is defined more than once")
                observed_variables[node.variable] = node.node_id

        if observed_variables != self.by_var:
            raise ValueError("variable index does not match DAG nodes")

    def evaluate(
        self,
        assignments: Mapping[int, bool | Tri],
    ) -> dict[int, Tri]:
        """Evaluate all nodes; missing input bits propagate as UNKNOWN."""
        self.validate()
        for variable, value in assignments.items():
            if type(variable) is not int or variable not in self.by_var:
                raise ValueError(f"assignment references unknown variable {variable!r}")
            if self.nodes[self.by_var[variable]].op is not Op.INPUT:
                raise ValueError(f"variable {variable} is not a DAG input")
            if type(value) is not bool and not isinstance(value, Tri):
                raise ValueError(f"assignment for variable {variable} must be bool or Tri")

        results: dict[int, Tri] = {}
        for node in self.nodes:
            if node.op is Op.INPUT:
                assert node.variable is not None
                assigned = assignments.get(node.variable, Tri.UNKNOWN)
                results[node.node_id] = (
                    Tri.from_bool(assigned)
                    if isinstance(assigned, bool)
                    else assigned
                )
                continue
            if node.op is Op.CONST:
                assert node.value is not None
                results[node.node_id] = Tri.from_bool(node.value)
                continue

            parent_values = tuple(results[parent] for parent in node.inputs)
            choices = tuple(
                (False, True) if value is Tri.UNKNOWN else (value.as_bool(),)
                for value in parent_values
            )
            outputs = {
                _apply(node.op, values)
                for values in product(*choices)
            }
            results[node.node_id] = (
                Tri.from_bool(outputs.pop()) if len(outputs) == 1 else Tri.UNKNOWN
            )
        return results

    def variable_values(self, results: Mapping[int, Tri]) -> dict[int, Tri]:
        """Return evaluated values indexed by associated DIMACS variable."""
        self.validate()
        return {
            variable: results[node_id]
            for variable, node_id in self.by_var.items()
            if node_id in results
        }

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of this validated DAG."""
        self.validate()
        return {
            "schema": "keylab-equation-dag-v1",
            "nodes": [
                {
                    "id": node.node_id,
                    "op": node.op.value,
                    "inputs": list(node.inputs),
                    "variable": node.variable,
                    "value": node.value,
                    "label": node.label,
                }
                for node in self.nodes
            ],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the DAG to JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


__all__ = ["DAGNode", "EquationDAG", "Op", "Tri"]
