"""DIMACS models for bounded SHA-256 compression and hash experiments."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TextIO

from keylab.sat.cnf import CNF

from .reduced import _SHA_IV, _SHA_K

_WORD = tuple[int, ...]
_INITIAL_STATE = b"".join(value.to_bytes(4, "big") for value in _SHA_IV)
_MAX_SHA256_BYTES = ((1 << 64) - 1) // 8


@dataclass
class SHA256CNFModel:
    """A SHA-256 CNF model, including free input bits and experiment parameters."""

    formula: CNF
    input_bits: tuple[int, ...]
    rounds: int
    mode: str
    target: bytes
    initial_state: bytes
    message_length: int | None
    fixed_bits: dict[int, int] = field(default_factory=dict)

    @property
    def variable_count(self) -> int:
        """Number of variables in the generated formula."""
        return self.formula.variable_count

    @property
    def clause_count(self) -> int:
        """Number of clauses in the generated formula."""
        return len(self.formula.clauses)

    @property
    def message_bits(self) -> tuple[int, ...]:
        """Compatibility alias for the free message/block input bits."""
        return self.input_bits

    def to_dimacs(self) -> str:
        """Serialize the formula as a DIMACS CNF string."""
        return self.formula.to_dimacs()

    def write_dimacs(self, output: TextIO) -> None:
        """Write the formula incrementally to a text stream."""
        self.formula.write_dimacs(output)

    def constrain_input_bits(self, assignments: Mapping[int, int]) -> None:
        """Fix selected input bits, indexed by byte then most-significant bit.

        Values must be 0 or 1. Conflicting repeat assignments are rejected before
        any clauses are changed.
        """
        for index, value in assignments.items():
            if not isinstance(index, int) or not 0 <= index < len(self.input_bits):
                raise ValueError(f"input bit index must be between 0 and {len(self.input_bits) - 1}")
            if value not in (0, 1):
                raise ValueError("input bit values must be 0 or 1")
            if index in self.fixed_bits and self.fixed_bits[index] != value:
                raise ValueError(f"input bit {index} is already fixed to {self.fixed_bits[index]}")

        for index, value in assignments.items():
            if index in self.fixed_bits:
                continue
            literal = self.input_bits[index]
            self.formula.add_clause(literal if value else -literal)
            self.fixed_bits[index] = value

    def recover_input(self, assignments: Mapping[int, bool]) -> bytes:
        """Extract a candidate input, assigning false to solver-omitted free bits."""
        output = bytearray()
        for byte_start in range(0, len(self.input_bits), 8):
            value = 0
            for variable in self.input_bits[byte_start : byte_start + 8]:
                value = (value << 1) | int(assignments.get(variable, False))
            output.append(value)
        return bytes(output)


@dataclass
class SHA256SecretPrefixModel:
    """A secret-prefix SHA-256 model for educational, bounded experiments."""

    model: SHA256CNFModel
    secret_length: int
    known_message: bytes

    @property
    def variable_count(self) -> int:
        return self.model.variable_count

    @property
    def clause_count(self) -> int:
        return self.model.clause_count

    @property
    def rounds(self) -> int:
        return self.model.rounds

    @property
    def fixed_bits(self) -> dict[int, int]:
        return self.model.fixed_bits

    def to_dimacs(self) -> str:
        return self.model.to_dimacs()

    def write_dimacs(self, output: TextIO) -> None:
        self.model.write_dimacs(output)

    def recover_secret(self, assignments: Mapping[int, bool]) -> bytes:
        """Recover the prefix from a SAT model assignment."""
        candidate = self.model.recover_input(assignments)
        if candidate[self.secret_length :] != self.known_message:
            raise ValueError("solver assignment does not match the fixed known message")
        return candidate[: self.secret_length]


def _word(value: int, true_literal: int) -> _WORD:
    return tuple(true_literal if value & (1 << bit) else -true_literal for bit in range(32))


def _xor3(cnf: CNF, first: int, second: int, third: int) -> int:
    return cnf.xor3(first, second, third)


def _small_sigma0(cnf: CNF, value: _WORD, false_literal: int) -> _WORD:
    return tuple(
        _xor3(
            cnf,
            value[(bit + 7) % 32],
            value[(bit + 18) % 32],
            value[bit + 3] if bit + 3 < 32 else false_literal,
        )
        for bit in range(32)
    )


def _small_sigma1(cnf: CNF, value: _WORD, false_literal: int) -> _WORD:
    return tuple(
        _xor3(
            cnf,
            value[(bit + 17) % 32],
            value[(bit + 19) % 32],
            value[bit + 10] if bit + 10 < 32 else false_literal,
        )
        for bit in range(32)
    )


def _big_sigma0(cnf: CNF, value: _WORD) -> _WORD:
    return tuple(
        _xor3(cnf, value[(bit + 2) % 32], value[(bit + 13) % 32], value[(bit + 22) % 32])
        for bit in range(32)
    )


def _big_sigma1(cnf: CNF, value: _WORD) -> _WORD:
    return tuple(
        _xor3(cnf, value[(bit + 6) % 32], value[(bit + 11) % 32], value[(bit + 25) % 32])
        for bit in range(32)
    )


def _add(cnf: CNF, left: _WORD, right: _WORD, false_literal: int) -> _WORD:
    return cnf.add_many((left, right), 32, false_literal)


def _rounds(rounds: int) -> None:
    if not isinstance(rounds, int) or not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")


def _state_words(state: bytes, label: str) -> tuple[int, ...]:
    if len(state) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes")
    return tuple(int.from_bytes(state[offset : offset + 4], "big") for offset in range(0, 32, 4))


def _compress_block_cnf(
    cnf: CNF,
    block_bits: list[int],
    state_words: tuple[_WORD, ...],
    rounds: int,
    true_literal: int,
    false_literal: int,
) -> tuple[_WORD, ...]:
    schedule: list[_WORD] = []
    for word_index in range(16):
        start = word_index * 32
        schedule.append(tuple(block_bits[start + 31 - bit] for bit in range(32)))
    for index in range(16, rounds):
        sigma1 = _small_sigma1(cnf, schedule[index - 2], false_literal)
        sigma0 = _small_sigma0(cnf, schedule[index - 15], false_literal)
        schedule.append(
            cnf.add_many(
                (schedule[index - 16], sigma1, schedule[index - 7], sigma0),
                32,
                false_literal,
            )
        )

    a, b, c, d, e, f, g, h = state_words
    for index in range(rounds):
        upper_sigma1 = _big_sigma1(cnf, e)
        choice = tuple(cnf.mux(e[bit], f[bit], g[bit]) for bit in range(32))
        temp1 = cnf.add_many(
            (h, upper_sigma1, choice, _word(_SHA_K[index], true_literal), schedule[index]),
            32,
            false_literal,
        )
        upper_sigma0 = _big_sigma0(cnf, a)
        majority = tuple(cnf.majority(a[bit], b[bit], c[bit]) for bit in range(32))
        temp2 = _add(cnf, upper_sigma0, majority, false_literal)
        next_a = _add(cnf, temp1, temp2, false_literal)
        next_e = _add(cnf, d, temp1, false_literal)
        a, b, c, d, e, f, g, h = next_a, a, b, c, next_e, e, f, g

    return tuple(
        _add(cnf, original, current, false_literal)
        for original, current in zip(state_words, (a, b, c, d, e, f, g, h))
    )


def _build_model(
    *,
    target_state: bytes,
    rounds: int,
    initial_state: bytes,
    message_length: int | None,
    fixed_bits: Mapping[int, int] | None,
    track_dag: bool,
    xor3_encoding: str,
) -> SHA256CNFModel:
    _rounds(rounds)
    target_words = _state_words(target_state, "target_state")
    initial_words = _state_words(initial_state, "initial_state")

    if message_length is None:
        input_bit_count = 512
        mode = "compression"
        block_count = 1
    else:
        assert message_length is not None
        if not 0 <= message_length <= _MAX_SHA256_BYTES:
            raise ValueError("message_length must fit the SHA-256 64-bit bit-length field")
        input_bit_count = message_length * 8
        mode = "hash"
        block_count = (message_length + 9 + 63) // 64

    cnf = CNF(track_dag=track_dag, xor3_encoding=xor3_encoding)
    true_literal = cnf.constant(True, label="true")
    false_literal = -true_literal
    input_bits = tuple(cnf.input_var(f"message[{index}]") for index in range(input_bit_count))
    normalized_fixed_bits: dict[int, int] = {}
    if fixed_bits:
        for index, value in fixed_bits.items():
            if not isinstance(index, int) or not 0 <= index < len(input_bits):
                raise ValueError(
                    f"input bit index must be between 0 and {len(input_bits) - 1}"
                )
            if value not in (0, 1):
                raise ValueError("input bit values must be 0 or 1")
            normalized_fixed_bits[index] = int(value)
            cnf.constrain_variable(input_bits[index], int(value))

    state_words = tuple(_word(value, true_literal) for value in initial_words)
    if message_length is None:
        block_bits = list(input_bits)
        state_words = _compress_block_cnf(
            cnf, block_bits, state_words, rounds, true_literal, false_literal
        )
    else:
        padded_length = block_count * 64
        bit_length = message_length * 8
        length_bytes = bit_length.to_bytes(8, "big")
        for block_index in range(block_count):
            block_bits = []
            for byte_in_block in range(64):
                stream_index = block_index * 64 + byte_in_block
                if stream_index < message_length:
                    value: int | None = None
                elif stream_index == message_length:
                    value = 0x80
                elif stream_index >= padded_length - 8:
                    value = length_bytes[stream_index - (padded_length - 8)]
                else:
                    value = 0

                if value is None:
                    byte_bits = input_bits[stream_index * 8 : stream_index * 8 + 8]
                else:
                    byte_bits = [
                        true_literal if (value >> (7 - bit)) & 1 else false_literal
                        for bit in range(8)
                    ]
                block_bits.extend(byte_bits)
            state_words = _compress_block_cnf(
                cnf, block_bits, state_words, rounds, true_literal, false_literal
            )

    output_state = state_words
    for word_index, word in enumerate(output_state):
        for bit_index, literal in enumerate(word):
            expected = (target_words[word_index] >> bit_index) & 1
            cnf.add_clause(literal if expected else -literal)

    model = SHA256CNFModel(
        formula=cnf,
        input_bits=input_bits,
        rounds=rounds,
        mode=mode,
        target=target_state,
        initial_state=initial_state,
        message_length=message_length,
        fixed_bits=normalized_fixed_bits.copy(),
    )
    return model


def sha256_compression_cnf(
    target_state: bytes,
    *,
    rounds: int = 64,
    initial_state: bytes = _INITIAL_STATE,
    fixed_bits: Mapping[int, int] | None = None,
    track_dag: bool = False,
    xor3_encoding: str = "direct",
) -> SHA256CNFModel:
    """Model one SHA-256 compression invocation for an arbitrary 512-bit block.

    ``target_state`` is the 32-byte feed-forward output. The initial chaining
    state, round count, and any fixed input bits are explicit.
    """
    return _build_model(
        target_state=target_state,
        rounds=rounds,
        initial_state=initial_state,
        message_length=None,
        fixed_bits=fixed_bits,
        track_dag=track_dag,
        xor3_encoding=xor3_encoding,
    )


def sha256_hash_preimage_cnf(
    target_digest: bytes,
    *,
    message_length: int,
    rounds: int = 64,
    fixed_bits: Mapping[int, int] | None = None,
    track_dag: bool = False,
    xor3_encoding: str = "direct",
) -> SHA256CNFModel:
    """Model a padded hash preimage for an exact, fixed message length.

    The input may span any number of 64-byte blocks. At 64 rounds this is a
    standard SHA-256 hash preimage model; smaller round counts are experiments
    using identical byte-stream padding and chaining.
    """
    return _build_model(
        target_state=target_digest,
        rounds=rounds,
        initial_state=_INITIAL_STATE,
        message_length=message_length,
        fixed_bits=fixed_bits,
        track_dag=track_dag,
        xor3_encoding=xor3_encoding,
    )


def sha256_secret_prefix_cnf(
    target_digest: bytes,
    *,
    known_message: bytes,
    secret_length: int,
    rounds: int = 64,
    track_dag: bool = False,
    xor3_encoding: str = "direct",
) -> SHA256SecretPrefixModel:
    """Model ``SHA256(secret || known_message)`` with a fixed secret length.

    This is an educational model of the insecure secret-prefix MAC pattern,
    not a practical method for recovering secrets. Use HMAC-SHA-256 for
    authentication; full-round preimage solving is computationally infeasible.
    """
    if not isinstance(secret_length, int) or secret_length < 0:
        raise ValueError("secret_length must be a nonnegative integer")
    message_length = secret_length + len(known_message)
    model = sha256_hash_preimage_cnf(
        target_digest,
        message_length=message_length,
        rounds=rounds,
        track_dag=track_dag,
        xor3_encoding=xor3_encoding,
    )
    fixed_message_bits = {
        (secret_length + byte_index) * 8 + bit_index: (byte >> (7 - bit_index)) & 1
        for byte_index, byte in enumerate(known_message)
        for bit_index in range(8)
    }
    model.constrain_input_bits(fixed_message_bits)
    return SHA256SecretPrefixModel(model, secret_length, known_message)


def sha256_55byte_preimage_cnf(target_digest: bytes) -> SHA256CNFModel:
    """Compatibility wrapper for an exactly 55-byte full-round hash model."""
    return sha256_hash_preimage_cnf(target_digest, message_length=55)


SHA256PreimageModel = SHA256CNFModel


__all__ = [
    "SHA256CNFModel",
    "SHA256PreimageModel",
    "SHA256SecretPrefixModel",
    "sha256_55byte_preimage_cnf",
    "sha256_compression_cnf",
    "sha256_hash_preimage_cnf",
    "sha256_secret_prefix_cnf",
]
