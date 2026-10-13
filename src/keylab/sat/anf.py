"""Exact conversion of quadratic Boolean ANF equations into ordinary CNF."""

from __future__ import annotations

from collections.abc import Iterable

from keylab.sat.cnf import CNF


class MQCNFEncoder:
    """Encode GF(2) equations of degree at most two using Tseitin auxiliaries.

    Input variable indices are one-based. Each equation is
    ``XOR(products, linear_variables) == rhs``. Duplicate monomials cancel
    modulo two, and Boolean diagonal products ``x*x`` reduce to ``x``.
    """

    def __init__(self, input_variable_count: int) -> None:
        if type(input_variable_count) is not int or input_variable_count < 0:
            raise ValueError("input_variable_count must be a nonnegative integer")
        self.input_variable_count = input_variable_count
        self.formula = CNF()
        for _ in range(input_variable_count):
            self.formula.fresh_var()
        self._product_variables: dict[tuple[int, int], int] = {}
        self.equation_count = 0

    @property
    def product_variables(self) -> dict[tuple[int, int], int]:
        """Return a copy of the shared quadratic-product variable map."""
        return self._product_variables.copy()

    def _validate_variable(self, variable: int) -> None:
        if type(variable) is not int or not 1 <= variable <= self.input_variable_count:
            raise ValueError(
                f"variable indices must be between 1 and {self.input_variable_count}"
            )

    def _product_variable(self, left: int, right: int) -> int:
        if left == right:
            return left
        pair = tuple(sorted((left, right)))
        if pair not in self._product_variables:
            product = self.formula.fresh_var()
            self.formula.add_clause(-pair[0], -pair[1], product)
            self.formula.add_clause(pair[0], -product)
            self.formula.add_clause(pair[1], -product)
            self._product_variables[pair] = product
        return self._product_variables[pair]

    def add_equation(
        self,
        quadratic_terms: Iterable[tuple[int, int]],
        linear_terms: Iterable[int],
        rhs: int,
    ) -> None:
        """Add one degree-2 ANF equation, rejecting malformed input atomically."""
        if type(rhs) is not int or rhs not in (0, 1):
            raise ValueError("rhs must be 0 or 1")

        quadratic_parity: set[tuple[int, int]] = set()
        for term in quadratic_terms:
            if not isinstance(term, tuple) or len(term) != 2:
                raise ValueError("each quadratic term must be a pair of variable indices")
            left, right = term
            self._validate_variable(left)
            self._validate_variable(right)
            pair = tuple(sorted((left, right)))
            if left == right:
                pair = (left, left)
            if pair in quadratic_parity:
                quadratic_parity.remove(pair)
            else:
                quadratic_parity.add(pair)

        linear_parity: set[int] = set()
        for variable in linear_terms:
            self._validate_variable(variable)
            if variable in linear_parity:
                linear_parity.remove(variable)
            else:
                linear_parity.add(variable)

        for left, right in quadratic_parity:
            if left == right:
                if left in linear_parity:
                    linear_parity.remove(left)
                else:
                    linear_parity.add(left)

        polynomial_variables = [
            self._product_variable(left, right)
            for left, right in sorted(quadratic_parity)
            if left != right
        ]
        polynomial_variables.extend(sorted(linear_parity))
        self._add_xor_constraint(polynomial_variables, rhs)
        self.equation_count += 1

    def _add_xor_constraint(self, variables: list[int], rhs: int) -> None:
        if not variables:
            if rhs:
                self.formula.add_clause()
            return

        result = variables[0]
        for variable in variables[1:]:
            result = self.formula.xor(result, variable)
        self.formula.add_clause(result if rhs else -result)

    def to_dimacs(self) -> str:
        """Serialize the equivalent ordinary DIMACS CNF formula."""
        return self.formula.to_dimacs()
