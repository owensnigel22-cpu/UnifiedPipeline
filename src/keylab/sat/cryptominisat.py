"""CryptoMiniSat extended-DIMACS export helpers for native XOR constraints.

Standard DIMACS CNF cannot carry XOR rows. Keep this format separate from
CNF-only solvers and from Keylab's standard-CNF cube runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TextIO


def literal_value(model: list[bool] | tuple[bool, ...] | None, literal: int) -> bool:
    """Evaluate a signed DIMACS literal; model index zero is unused."""
    if type(literal) is not int or literal == 0:
        raise ValueError("literal must be a non-zero integer")
    if model is None or abs(literal) >= len(model):
        raise ValueError("model does not assign the requested variable")
    value = bool(model[abs(literal)])
    return value if literal > 0 else not value


@dataclass
class CryptoMiniSatFormula:
    """Small formula container that emits mixed CNF and CryptoMiniSat XOR rows."""

    variable_count: int = 0
    clauses: list[tuple[int, ...]] = field(default_factory=list)
    xors: list[tuple[tuple[int, ...], bool]] = field(default_factory=list)

    def _validate_literals(self, literals: tuple[int, ...]) -> None:
        if any(type(lit) is not int or lit == 0 or abs(lit) > self.variable_count for lit in literals):
            raise ValueError("literals must be nonzero and reference allocated variables")

    def add_clause(self, literals: tuple[int, ...] | list[int]) -> None:
        row = tuple(literals)
        self._validate_literals(row)
        self.clauses.append(row)

    def add_xor(self, variables: tuple[int, ...] | list[int], rhs: bool = True) -> None:
        """Add XOR of positive variables equal to ``rhs``; repeated vars cancel."""
        if type(rhs) is not bool:
            raise TypeError("rhs must be bool")
        self._validate_literals(tuple(variables))
        parity: set[int] = set()
        for variable in variables:
            if variable <= 0:
                raise ValueError("add_xor expects positive variable identifiers")
            if variable in parity:
                parity.remove(variable)
            else:
                parity.add(variable)
        self.xors.append((tuple(sorted(parity)), rhs))

    def write_dimacs(self, stream: TextIO) -> None:
        """Write CryptoMiniSat extended DIMACS (XOR rows start with ``x``).

        To encode XOR(vars)=False in a format whose XOR rows have odd parity,
        the first literal is negated. The ``x -`` prefix from some pasted
        examples is not the standard CryptoMiniSat literal syntax.
        """
        emitted_xors = sum(bool(variables) or rhs for variables, rhs in self.xors)
        stream.write(f"p cnf {self.variable_count} {len(self.clauses) + emitted_xors}\n")
        stream.writelines(" ".join(map(str, clause)) + " 0\n" for clause in self.clauses)
        for variables, rhs in self.xors:
            if not variables:
                if rhs:
                    # Empty XOR is false, so XOR()=true is a contradiction.
                    stream.write("0\n")
                else:
                    # XOR()=false is tautological; an empty clause cannot encode it.
                    continue
            else:
                literals = list(variables)
                if not rhs:
                    literals[0] = -literals[0]
                stream.write("x " + " ".join(map(str, literals)) + " 0\n")


__all__ = ["CryptoMiniSatFormula", "literal_value"]
