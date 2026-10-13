"""Tseitin CNF utilities with carry-save addition for bounded research models."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TextIO

from keylab.sat.dag import EquationDAG, Op


class CNF:
    """Build a DIMACS-compatible CNF formula with memoized Boolean circuit gadgets."""

    def __init__(
        self,
        *,
        track_dag: bool = False,
        xor3_encoding: str = "direct",
    ) -> None:
        if xor3_encoding not in ("direct", "chain"):
            raise ValueError("xor3_encoding must be 'direct' or 'chain'")
        self.variable_count = 0
        self.clauses: list[tuple[int, ...]] = []
        self._memo: dict[tuple[object, ...], int] = {}
        self._adder_memo: dict[tuple[int, int, int], tuple[int, int]] = {}
        self.dag = EquationDAG() if track_dag else None
        self.xor3_encoding = xor3_encoding
        self._constant_values: dict[int, bool] = {}
        self._constant_literals: dict[bool, int] = {}

    def fresh_var(self) -> int:
        """Allocate and return a positive DIMACS variable identifier."""
        self.variable_count += 1
        return self.variable_count

    def input_var(self, label: str = "") -> int:
        """Allocate a formula input variable and register it in the optional DAG."""
        variable = self.fresh_var()
        if self.dag is not None:
            self.dag.add_input(variable, label)
        return variable

    def constant(self, value: bool, label: str = "") -> int:
        """Allocate a unit-constrained Boolean constant."""
        if type(value) is not bool:
            raise ValueError("constant value must be bool")
        if value in self._constant_literals:
            return self._constant_literals[value]
        variable = self.fresh_var()
        self._constant_values[variable] = value
        self._constant_literals[value] = variable
        self.add_clause(variable if value else -variable)
        if self.dag is not None:
            self.dag.add_constant(variable, value, label)
        return variable

    def add_clause(self, *literals: int) -> None:
        """Append a clause after validating that every literal refers to an allocated variable."""
        if any(literal == 0 or abs(literal) > self.variable_count for literal in literals):
            raise ValueError("clause contains zero or an unallocated variable")
        self.clauses.append(tuple(literals))
        if len(literals) == 1:
            variable = abs(literals[0])
            value = literals[0] > 0
            self._constant_values.setdefault(variable, value)

    def _add_gate_clause(self, *literals: int) -> None:
        """Append a clause whose literals were validated by its gate constructor."""
        self.clauses.append(tuple(literals))

    def constrain_variable(self, variable: int, value: int) -> None:
        """Add a unit constraint and make its value available to gate simplification."""
        if type(variable) is not int or not 1 <= variable <= self.variable_count:
            raise ValueError("constrained variable must be allocated")
        if type(value) is not int or value not in (0, 1):
            raise ValueError("constraint value must be 0 or 1")
        self.add_clause(variable if value else -variable)

    def _known_literal_value(self, literal: int) -> bool | None:
        known = self._constant_values.get(abs(literal))
        if known is None:
            return None
        return known if literal > 0 else not known

    def _validate_literals(self, literals: tuple[int, ...], gate: str) -> None:
        if any(literal == 0 or abs(literal) > self.variable_count for literal in literals):
            raise ValueError(f"{gate} input references an unallocated variable")

    def _literal_for_constant(self, value: bool) -> int:
        variable = self._constant_literals.get(value)
        if variable is None:
            variable = next(
                (
                    known_variable
                    if known_value == value
                    else -known_variable
                    for known_variable, known_value in self._constant_values.items()
                ),
                None,
            )
        if variable is None:
            variable = self.constant(value)
        return variable

    def _and_or(self, operation: str, left: int, right: int) -> int:
        """Simplify AND/OR identities, otherwise add the corresponding gate."""
        left_value = self._known_literal_value(left)
        right_value = self._known_literal_value(right)
        self._validate_literals((left, right), operation.upper())
        if operation == "and":
            if left_value is False or right_value is False or left == -right:
                return self._literal_for_constant(False)
            if left_value is True:
                return right
            if right_value is True:
                return left
            if left == right:
                return left
            op = Op.AND
        else:
            if left_value is True or right_value is True or left == -right:
                return self._literal_for_constant(True)
            if left_value is False:
                return right
            if right_value is False:
                return left
            if left == right:
                return left
            op = Op.OR

        key = (operation, *sorted((left, right)))

        def build() -> int:
            output = self.fresh_var()
            if operation == "and":
                self._add_gate_clause(-left, -right, output)
                self._add_gate_clause(left, -output)
                self._add_gate_clause(right, -output)
            else:
                self._add_gate_clause(left, right, -output)
                self._add_gate_clause(-left, output)
                self._add_gate_clause(-right, output)
            self._record_gate(op, (left, right), output)
            return output

        return self._memoized(key, build)

    def _memoized(self, key: tuple[object, ...], build) -> int:
        result = self._memo.get(key)
        if result is None:
            result = build()
            self._memo[key] = result
        return result

    def _record_gate(self, op: Op, literals: tuple[int, ...], output: int) -> None:
        if self.dag is not None:
            self.dag.add_literal_gate(op, literals, variable=output)

    def xor(self, left: int, right: int) -> int:
        """Create a Tseitin variable equal to XOR(left, right)."""
        self._validate_literals((left, right), "XOR")
        left_value = self._known_literal_value(left)
        right_value = self._known_literal_value(right)
        if left_value is not None:
            return right if not left_value else -right
        if right_value is not None:
            return left if not right_value else -left
        if left == right:
            return self._literal_for_constant(False)
        if left == -right:
            return self._literal_for_constant(True)
        output_negated = (left < 0) != (right < 0)
        first, second = sorted((abs(left), abs(right)))
        key = ("xor", first, second)

        def build() -> int:
            output = self.fresh_var()
            self._add_gate_clause(-first, -second, -output)
            self._add_gate_clause(first, second, -output)
            self._add_gate_clause(first, -second, output)
            self._add_gate_clause(-first, second, output)
            self._record_gate(Op.XOR, (first, second), output)
            return output

        output = self._memoized(key, build)
        return -output if output_negated else output

    def and_gate(self, left: int, right: int) -> int:
        """Create a Tseitin variable equal to AND(left, right)."""
        return self._and_or("and", left, right)

    def or_gate(self, left: int, right: int) -> int:
        """Create a Tseitin variable equal to OR(left, right)."""
        return self._and_or("or", left, right)

    def xor3(self, first: int, second: int, third: int) -> int:
        """Encode a 3-input XOR directly or as two chained XOR2 gates."""
        self._validate_literals((first, second, third), "XOR")
        parity = False
        counts: dict[int, bool] = {}
        for literal in (first, second, third):
            if literal < 0:
                parity = not parity
            variable = abs(literal)
            known = self._constant_values.get(variable)
            if known is not None:
                parity ^= known
                continue
            counts[variable] = not counts.get(variable, False)
        remaining = [variable for variable, appears_odd_times in counts.items() if appears_odd_times]
        if not remaining:
            return self._literal_for_constant(parity)
        literals = sorted(remaining)
        if len(literals) == 1:
            return -literals[0] if parity else literals[0]
        if len(literals) == 2:
            result = self.xor(literals[0], literals[1])
            return -result if parity else result
        first, second, third = literals
        key = ("xor3", first, second, third)
        if self.xor3_encoding == "chain":
            output = self._memoized(
                key,
                lambda: self.xor(self.xor(first, second), third),
            )
            return -output if parity else output

        def build() -> int:
            output = self.fresh_var()
            a, b, c = first, second, third
            self.clauses.extend(
                (
                    (a, b, c, -output),
                    (a, b, -c, output),
                    (a, -b, c, output),
                    (a, -b, -c, -output),
                    (-a, b, c, output),
                    (-a, b, -c, -output),
                    (-a, -b, c, -output),
                    (-a, -b, -c, output),
                )
            )
            if self.dag is not None:
                self.dag.add_literal_gate(Op.XOR3, (first, second, third), variable=output)
            return output

        output = self._memoized(key, build)
        return -output if parity else output

    def majority(self, first: int, second: int, third: int) -> int:
        """Create a memoized MAJ3 output variable."""
        self._validate_literals((first, second, third), "majority")
        literals = (first, second, third)
        known_values = [self._known_literal_value(literal) for literal in literals]
        if known_values.count(True) >= 2:
            return self._literal_for_constant(True)
        if known_values.count(False) >= 2:
            return self._literal_for_constant(False)

        unknowns = [
            literal
            for literal, known in zip(literals, known_values)
            if known is None
        ]
        if len(unknowns) == 2:
            if known_values.count(True) == 1:
                return self.or_gate(*unknowns)
            return self.and_gate(*unknowns)

        for first_index in range(3):
            for second_index in range(first_index + 1, 3):
                left, right = literals[first_index], literals[second_index]
                remaining = literals[3 - first_index - second_index]
                if left == right:
                    return left
                if left == -right:
                    return remaining

        key = ("maj3", *sorted((first, second, third)))

        def build() -> int:
            output = self.fresh_var()
            self._add_gate_clause(-first, -second, output)
            self._add_gate_clause(-first, -third, output)
            self._add_gate_clause(-second, -third, output)
            self._add_gate_clause(first, second, -output)
            self._add_gate_clause(first, third, -output)
            self._add_gate_clause(second, third, -output)
            self._record_gate(Op.MAJ3, (first, second, third), output)
            return output

        return self._memoized(key, build)

    def mux(self, selector: int, when_true: int, when_false: int) -> int:
        """Create a memoized output equal to selector ? when_true : when_false."""
        self._validate_literals((selector, when_true, when_false), "MUX")
        selector_value = self._known_literal_value(selector)
        if selector_value is not None:
            return when_true if selector_value else when_false
        if when_true == when_false:
            return when_true

        true_value = self._known_literal_value(when_true)
        false_value = self._known_literal_value(when_false)
        if true_value is not None and false_value is not None:
            if true_value == false_value:
                return self._literal_for_constant(true_value)
            return selector if true_value else -selector
        if true_value is True:
            return self.or_gate(selector, when_false)
        if true_value is False:
            return self.and_gate(-selector, when_false)
        if false_value is True:
            return self.or_gate(-selector, when_true)
        if false_value is False:
            return self.and_gate(selector, when_true)

        key = ("mux", selector, when_true, when_false)

        def build() -> int:
            output = self.fresh_var()
            self._add_gate_clause(-selector, -when_true, output)
            self._add_gate_clause(-selector, when_true, -output)
            self._add_gate_clause(selector, -when_false, output)
            self._add_gate_clause(selector, when_false, -output)
            self._record_gate(Op.MUX, (selector, when_true, when_false), output)
            return output

        return self._memoized(key, build)

    def full_adder(self, left: int, right: int, carry_in: int) -> tuple[int, int]:
        """Return (sum, carry-out) variables for a Boolean full adder."""
        key = (min(left, right), max(left, right), carry_in)
        if key in self._adder_memo:
            return self._adder_memo[key]
        pair_xor = self.xor(left, right)
        sum_bit = self.xor(pair_xor, carry_in)
        carry_out = self.majority(left, right, carry_in)
        self._adder_memo[key] = (sum_bit, carry_out)
        return self._adder_memo[key]

    def add_many(
        self,
        words: Sequence[Sequence[int]],
        width: int,
        false_literal: int,
    ) -> tuple[int, ...]:
        """Add bit-vectors modulo 2**width using carry-save reduction.

        Vectors are least-significant-bit first. The carry-save stages compress
        groups of three operands without propagating carries across the word;
        one ripple-carry addition combines the final two operands. Carry bits
        beyond ``width`` are intentionally omitted, implementing arithmetic
        modulo ``2**width`` without allocating a carry-out variable.
        """
        if width < 1:
            raise ValueError("width must be positive")
        if false_literal == 0 or abs(false_literal) > self.variable_count:
            raise ValueError("false_literal must reference an allocated variable")
        if any(len(word) > width for word in words):
            raise ValueError("operand width must not exceed the result width")
        if any(
            literal == 0 or abs(literal) > self.variable_count
            for word in words
            for literal in word
        ):
            raise ValueError("operand contains zero or an unallocated variable")

        current = [list(word) + [false_literal] * (width - len(word)) for word in words]
        if not current:
            return (false_literal,) * width

        while len(current) > 2:
            reduced: list[list[int]] = []
            index = 0
            while index + 2 < len(current):
                first, second, third = current[index : index + 3]
                sum_bits: list[int] = []
                carry_bits = [false_literal]
                for bit in range(width):
                    sum_bits.append(self.xor3(first[bit], second[bit], third[bit]))
                    if bit + 1 < width:
                        carry_bits.append(self.majority(first[bit], second[bit], third[bit]))
                reduced.extend((sum_bits, carry_bits))
                index += 3
            reduced.extend(current[index:])
            current = reduced

        if len(current) == 1:
            return tuple(current[0])

        carry = false_literal
        result: list[int] = []
        for bit_index, (left_bit, right_bit) in enumerate(zip(current[0], current[1])):
            if bit_index == width - 1:
                pair_xor = self.xor(left_bit, right_bit)
                sum_bit = self.xor(pair_xor, carry)
            else:
                sum_bit, carry = self.full_adder(left_bit, right_bit, carry)
            result.append(sum_bit)
        return tuple(result)

    def to_dimacs(self) -> str:
        """Serialize the current formula in DIMACS CNF format."""
        from io import StringIO

        output = StringIO()
        self.write_dimacs(output)
        return output.getvalue()

    def write_dimacs(self, output: TextIO) -> None:
        """Write DIMACS incrementally to a text stream without building one large string."""
        output.write(f"p cnf {self.variable_count} {len(self.clauses)}\n")
        for clause in self.clauses:
            output.write(" ".join(map(str, clause)))
            output.write(" 0\n")