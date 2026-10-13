"""Bounded RIPEMD-160 reduced-step, fixed-length preimage CNF models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TextIO

from keylab.hashes.reduced import _K1, _K2, _R1, _R2, _S1, _S2
from keylab.sat.cnf import CNF

_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_WIDTH = 32


def _constant_word(value: int, false_literal: int) -> tuple[int, ...]:
    return tuple(
        -false_literal if value & (1 << bit) else false_literal
        for bit in range(_WIDTH)
    )


def _rotate_left(word: tuple[int, ...], amount: int) -> tuple[int, ...]:
    return tuple(word[(bit - amount) % _WIDTH] for bit in range(_WIDTH))


def _boolean_function(
    cnf: CNF,
    function_index: int,
    x: tuple[int, ...],
    y: tuple[int, ...],
    z: tuple[int, ...],
    true_literal: int,
) -> tuple[int, ...]:
    output: list[int] = []
    for x_bit, y_bit, z_bit in zip(x, y, z):
        if function_index == 0:
            bit = cnf.xor3(x_bit, y_bit, z_bit)
        elif function_index == 1:
            bit = cnf.mux(x_bit, y_bit, z_bit)
        elif function_index == 2:
            bit = cnf.xor(cnf.mux(y_bit, x_bit, true_literal), z_bit)
        elif function_index == 3:
            bit = cnf.mux(z_bit, x_bit, y_bit)
        else:
            bit = cnf.xor(x_bit, cnf.mux(z_bit, y_bit, true_literal))
        output.append(bit)
    return tuple(output)


def _compress(
    cnf: CNF,
    state: tuple[tuple[int, ...], ...],
    words: tuple[tuple[int, ...], ...],
    steps: int,
    false_literal: int,
) -> tuple[tuple[int, ...], ...]:
    left = list(state)
    right = list(state)
    true_literal = -false_literal
    for index in range(steps):
        round_index = index // 16
        left_function = _boolean_function(
            cnf, round_index, left[1], left[2], left[3], true_literal
        )
        left_sum = cnf.add_many(
            (left[0], left_function, words[_R1[index]], _constant_word(_K1[round_index], false_literal)),
            _WIDTH,
            false_literal,
        )
        left_step = cnf.add_many(
            (_rotate_left(left_sum, _S1[index]), left[4]), _WIDTH, false_literal
        )
        left = [left[4], left_step, left[1], _rotate_left(left[2], 10), left[3]]

        right_function = _boolean_function(
            cnf, 4 - round_index, right[1], right[2], right[3], true_literal
        )
        right_sum = cnf.add_many(
            (right[0], right_function, words[_R2[index]], _constant_word(_K2[round_index], false_literal)),
            _WIDTH,
            false_literal,
        )
        right_step = cnf.add_many(
            (_rotate_left(right_sum, _S2[index]), right[4]), _WIDTH, false_literal
        )
        right = [right[4], right_step, right[1], _rotate_left(right[2], 10), right[3]]

    a_l, b_l, c_l, d_l, e_l = left
    a_r, b_r, c_r, d_r, e_r = right
    initial = tuple(_constant_word(value, false_literal) for value in _IV)
    return (
        cnf.add_many((initial[1], c_l, d_r), _WIDTH, false_literal),
        cnf.add_many((initial[2], d_l, e_r), _WIDTH, false_literal),
        cnf.add_many((initial[3], e_l, a_r), _WIDTH, false_literal),
        cnf.add_many((initial[4], a_l, b_r), _WIDTH, false_literal),
        cnf.add_many((initial[0], b_l, c_r), _WIDTH, false_literal),
    )


@dataclass
class RIPEMD160PreimageModel:
    """CNF for an exact-length message of at most 55 bytes and a reduced-step digest."""

    formula: CNF
    input_bits: tuple[int, ...]
    target: bytes
    message_length: int
    steps: int
    fixed_bits: dict[int, int] = field(default_factory=dict)

    @property
    def variable_count(self) -> int:
        return self.formula.variable_count

    @property
    def clause_count(self) -> int:
        return len(self.formula.clauses)

    def constrain_input_bits(self, constraints: dict[int, int]) -> None:
        """Fix MSB-first bits in byte order, after validating the whole update."""
        for index, value in constraints.items():
            if not 0 <= index < len(self.input_bits):
                raise ValueError(f"input bit index {index} is out of range")
            if value not in (0, 1):
                raise ValueError(f"input bit value for index {index} must be 0 or 1")
            if index in self.fixed_bits and self.fixed_bits[index] != value:
                raise ValueError(f"input bit {index} is already fixed to a different value")
        for index, value in constraints.items():
            if index not in self.fixed_bits:
                literal = self.input_bits[index]
                self.formula.add_clause(literal if value else -literal)
                self.fixed_bits[index] = value

    def recover_input(self, assignments: dict[int, bool]) -> bytes:
        """Recover input bytes from a complete SAT assignment."""
        values: list[int] = []
        for offset in range(0, len(self.input_bits), 8):
            byte = 0
            for literal in self.input_bits[offset : offset + 8]:
                if abs(literal) not in assignments:
                    raise ValueError(f"solver assignment is missing variable {abs(literal)}")
                byte = (byte << 1) | int(assignments[abs(literal)] == (literal > 0))
            values.append(byte)
        return bytes(values)

    def write_dimacs(self, stream: TextIO) -> None:
        self.formula.write_dimacs(stream)

    def to_dimacs(self) -> str:
        return self.formula.to_dimacs()


def ripemd160_preimage_cnf(
    target: bytes,
    *,
    message_length: int,
    steps: int = 80,
) -> RIPEMD160PreimageModel:
    """Build a one-block padded RIPEMD-160 preimage model for 0..55 input bytes."""
    if len(target) != 20:
        raise ValueError("target must be exactly 20 bytes")
    if not 0 <= message_length <= 55:
        raise ValueError("message_length must be between 0 and 55 bytes")
    if not 1 <= steps <= 80:
        raise ValueError("steps must be between 1 and 80")

    cnf = CNF()
    false_literal = cnf.fresh_var()
    cnf.add_clause(-false_literal)
    input_bits: list[int] = []
    padded_bytes: list[tuple[int, ...]] = []
    for byte_index in range(64):
        if byte_index < message_length:
            byte_bits = tuple(cnf.fresh_var() for _ in range(8))
            input_bits.extend(byte_bits)
            padded_bytes.append(byte_bits)
        else:
            if byte_index == message_length:
                value = 0x80
            elif byte_index >= 56:
                value = (message_length * 8 >> (8 * (byte_index - 56))) & 0xFF
            else:
                value = 0
            padded_bytes.append(
                tuple(
                    -false_literal if value & (1 << (7 - bit)) else false_literal
                    for bit in range(8)
                )
            )

    message_words = tuple(
        tuple(
            literal
            for byte in padded_bytes[word_index * 4 : word_index * 4 + 4]
            for literal in reversed(byte)
        )
        for word_index in range(16)
    )
    initial_state = tuple(_constant_word(value, false_literal) for value in _IV)
    output_words = _compress(cnf, initial_state, message_words, steps, false_literal)
    for word_index, word in enumerate(output_words):
        expected = int.from_bytes(target[word_index * 4 : word_index * 4 + 4], "little")
        for bit, literal in enumerate(word):
            cnf.add_clause(literal if expected & (1 << bit) else -literal)

    return RIPEMD160PreimageModel(
        formula=cnf,
        input_bits=tuple(input_bits),
        target=target,
        message_length=message_length,
        steps=steps,
    )
