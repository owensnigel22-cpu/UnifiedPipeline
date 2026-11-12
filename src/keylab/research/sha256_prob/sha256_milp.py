"""Pure-Python MILP emitter for the reduced-round SHA-256 compression.

:func:`compression_milp` walks the shared bit circuit
(:mod:`keylab.research.sha256_prob._circuit`) and encodes it as a 0/1 mixed-integer
program: one binary variable per wire, standard linearizations per gate

- ``xor``:  ``sum(inputs) - out - 2*slack = 0`` (``slack`` binary; valid for fan-in <= 3);
- ``maj``:  ``0 <= in0 + in1 + in2 - 2*out <= 1``;
- ``ch``:   the four-inequality multiplexer ``out = in0 ? in1 : in2``;
- ``const`` and conditioned output bits: equality pins.

The model is emitted to CPLEX ``.lp`` and free-format ``.mps`` text with **no solver
dependency** (:meth:`MILPModel.write_lp` / :meth:`MILPModel.write_mps`). Solving is
optional: :meth:`MILPModel.solve` imports ``pulp`` (the ``milp`` extra) and, when a
target is pinned, returns a forward-verified preimage. Without ``pulp`` installed,
``solve`` raises ``ModuleNotFoundError`` and callers skip it; emission still works.

This is a feasibility/constraint model of the reduced-round compression — useful for
small reduced-round preimage and consistency studies. It is **not** a differential
active-S-box bound model, and no full 64-round instance is tractable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from keylab.research.sha256_prob._circuit import Circuit, build_compression_circuit


@dataclass(frozen=True)
class MILPVariable:
    """A binary decision variable."""

    name: str


@dataclass(frozen=True)
class Constraint:
    """A linear constraint ``sum(coeff * var) <sense> rhs`` with ``sense`` in <=,>=,=."""

    name: str
    terms: tuple[tuple[int, str], ...]
    sense: str
    rhs: int

    def __post_init__(self) -> None:
        if self.sense not in ("<=", ">=", "="):
            raise ValueError("sense must be one of '<=', '>=', '='")


@dataclass
class MILPSolveResult:
    """Result of solving a :class:`MILPModel` (requires the ``milp`` extra)."""

    status: str
    feasible: bool
    block: bytes | None
    verified: bool


@dataclass
class MILPModel:
    """A 0/1 MILP for the reduced-round compression, emittable to LP/MPS."""

    name: str
    rounds: int
    variables: list[MILPVariable]
    constraints: list[Constraint]
    circuit: Circuit
    conditioned: dict[int, int]  # output/const var -> pinned value
    _var_index: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._var_index = {v.name: i for i, v in enumerate(self.variables)}

    # --- emission -------------------------------------------------------------

    def to_lp(self) -> str:
        lines = [f"\\ KeyLab reduced-round SHA-256 compression MILP (rounds={self.rounds})"]
        lines.append("Minimize")
        lines.append(" obj: 0")
        lines.append("Subject To")
        for constraint in self.constraints:
            lines.append(f" {constraint.name}: {self._format_terms(constraint.terms)} "
                         f"{constraint.sense} {constraint.rhs}")
        lines.append("Binaries")
        lines.extend(_wrap(" ", (v.name for v in self.variables)))
        lines.append("End")
        return "\n".join(lines) + "\n"

    def to_mps(self) -> str:
        lines = [f"NAME          {self.name}", "ROWS", " N  COST"]
        sense_code = {"<=": "L", ">=": "G", "=": "E"}
        for constraint in self.constraints:
            lines.append(f" {sense_code[constraint.sense]}  {constraint.name}")
        lines.append("COLUMNS")
        lines.append("    MARKER                 'MARKER'                 'INTORG'")
        column_terms = self._columns()
        for var in self.variables:
            for row, coeff in column_terms.get(var.name, ()):
                lines.append(f"    {var.name}  {row}  {coeff}")
        lines.append("    MARKER                 'MARKER'                 'INTEND'")
        lines.append("RHS")
        for constraint in self.constraints:
            if constraint.rhs != 0:
                lines.append(f"    RHS  {constraint.name}  {constraint.rhs}")
        lines.append("BOUNDS")
        for var in self.variables:
            lines.append(f" BV BND  {var.name}")
        lines.append("ENDATA")
        return "\n".join(lines) + "\n"

    def write_lp(self, path: str | Path) -> Path:
        target = Path(path)
        target.write_text(self.to_lp(), encoding="ascii")
        return target

    def write_mps(self, path: str | Path) -> Path:
        target = Path(path)
        target.write_text(self.to_mps(), encoding="ascii")
        return target

    def _format_terms(self, terms: tuple[tuple[int, str], ...]) -> str:
        parts = []
        for coeff, var in terms:
            sign = "+" if coeff >= 0 else "-"
            parts.append(f"{sign} {abs(coeff)} {var}")
        return " ".join(parts) if parts else "0"

    def _columns(self) -> dict[str, list[tuple[str, int]]]:
        columns: dict[str, list[tuple[str, int]]] = {}
        for constraint in self.constraints:
            for coeff, var in constraint.terms:
                columns.setdefault(var, []).append((constraint.name, coeff))
        return columns

    # --- optional solving -----------------------------------------------------

    def solve(self) -> MILPSolveResult:
        """Solve with ``pulp`` (the ``milp`` extra). Raises if ``pulp`` is absent."""
        import pulp

        problem = pulp.LpProblem(self.name, pulp.LpMinimize)
        lp_vars = {v.name: pulp.LpVariable(v.name, cat="Binary") for v in self.variables}
        problem += 0, "obj"
        for constraint in self.constraints:
            expr = pulp.lpSum(coeff * lp_vars[var] for coeff, var in constraint.terms)
            if constraint.sense == "<=":
                problem += expr <= constraint.rhs, constraint.name
            elif constraint.sense == ">=":
                problem += expr >= constraint.rhs, constraint.name
            else:
                problem += expr == constraint.rhs, constraint.name
        status = problem.solve(pulp.PULP_CBC_CMD(msg=False))
        status_name = pulp.LpStatus[status]
        feasible = status_name == "Optimal"
        block = None
        verified = False
        if feasible:
            decode = {
                var: round(lp_vars[f"b{var}"].value() or 0)
                for var, _word, _bit in self.circuit.input_bits
            }
            words = [0] * 16
            for var, word, bit in self.circuit.input_bits:
                if decode[var]:
                    words[word] |= 1 << bit
            block = b"".join(w.to_bytes(4, "big") for w in words)
            produced = self.circuit.evaluate(decode)
            output_order = [v for wd in self.circuit.output_words for v in wd]
            verified = all(
                (produced[divmod(output_order.index(var), 32)[0]]
                 >> divmod(output_order.index(var), 32)[1]) & 1 == value
                for var, value in self.conditioned.items()
                if var in output_order
            )
        return MILPSolveResult(status_name, feasible, block, verified)


def compression_milp(
    rounds: int,
    *,
    free_input_bits: int = 512,
    target: bytes | None = None,
    target_bits: int = 0,
) -> MILPModel:
    """Build the reduced-round compression MILP.

    ``free_input_bits`` message bits are free; the rest are pinned to 0. When
    ``target`` and ``target_bits`` are given, the low ``target_bits`` output bits are
    pinned to that digest's bits (making :meth:`MILPModel.solve` search for a
    preimage); otherwise the model is the unconstrained compression relation.
    """
    if type(target_bits) is not int or not 0 <= target_bits <= 256:
        raise ValueError("target_bits must be between 0 and 256")
    circuit = build_compression_circuit(rounds, free_input_bits=free_input_bits)
    variables = [MILPVariable(f"b{var}") for var in range(circuit.num_vars)]
    constraints: list[Constraint] = []
    slack_count = 0

    def name(var: int) -> str:
        return f"b{var}"

    for kind, out, data in circuit.gates:
        index = len(constraints)
        if kind == "const":
            constraints.append(Constraint(f"c{index}", ((1, name(out)),), "=", data[0]))
        elif kind == "input":
            continue
        elif kind == "xor":
            slack = MILPVariable(f"s{slack_count}")
            slack_count += 1
            variables.append(slack)
            terms = tuple((1, name(src)) for src in data) + ((-1, name(out)), (-2, slack.name))
            constraints.append(Constraint(f"c{index}", terms, "=", 0))
        elif kind == "maj":
            a, b, c = (name(s) for s in data)
            terms = ((1, a), (1, b), (1, c), (-2, name(out)))
            constraints.append(Constraint(f"c{index}", terms, ">=", 0))
            constraints.append(Constraint(f"c{index}b", terms, "<=", 1))
        elif kind == "ch":
            e, f, g = (name(s) for s in data)
            o = name(out)
            # out = e ? f : g
            constraints.append(Constraint(f"c{index}", ((1, o), (-1, f), (1, e)), "<=", 1))
            constraints.append(Constraint(f"c{index}b", ((1, o), (-1, f), (-1, e)), ">=", -1))
            constraints.append(Constraint(f"c{index}c", ((1, o), (-1, g), (-1, e)), "<=", 0))
            constraints.append(Constraint(f"c{index}d", ((1, o), (-1, g), (1, e)), ">=", 0))

    conditioned: dict[int, int] = {}
    if target_bits:
        if target is None or len(target) != 32:
            raise ValueError("target must be a 32-byte digest when target_bits > 0")
        target_words = [int.from_bytes(target[i : i + 4], "big") for i in range(0, 32, 4)]
        output_order = [var for word in circuit.output_words for var in word]
        for i in range(target_bits):
            var = output_order[i]
            word_index, bit_index = divmod(i, 32)
            value = (target_words[word_index] >> bit_index) & 1
            conditioned[var] = value
            constraints.append(Constraint(f"t{i}", ((1, name(var)),), "=", value))

    return MILPModel(
        name="sha256_compression_milp",
        rounds=rounds,
        variables=variables,
        constraints=constraints,
        circuit=circuit,
        conditioned=conditioned,
    )


def _wrap(prefix: str, names, per_line: int = 10) -> list[str]:
    names = list(names)
    lines = []
    for start in range(0, len(names), per_line):
        lines.append(prefix + " ".join(names[start : start + per_line]))
    return lines


__all__ = [
    "Constraint",
    "MILPModel",
    "MILPSolveResult",
    "MILPVariable",
    "compression_milp",
]
