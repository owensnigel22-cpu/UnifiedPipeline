"""Reference reduced-round SHA-256 and RIPEMD-160; no full-hash preimage attack is implemented."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

_MASK = 0xFFFFFFFF
_SHA_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
_SHA_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_SHA256_MAX_BYTES = ((1 << 64) - 1) // 8
_STREAM_READ_SIZE = 64 * 1024


@dataclass(frozen=True)
class SHA256BackwardStep:
    """One numerically recovered SHA-256 working-state word."""

    round_index: int
    t1: int
    t2: int
    recovered_a_index: int
    recovered_a: int


@dataclass(frozen=True)
class SHA256BackwardTrace:
    """Numerical reverse trace and first unresolved one-block state boundary."""

    working_state: tuple[int, ...]
    known_a_values: tuple[tuple[int, int], ...]
    steps: tuple[SHA256BackwardStep, ...]
    boundary_round: int
    boundary_a_index: int
    boundary_t1: int
    bridge_round: int
    bridge_h_index: int
    bridge_h_offset: int
    bridge_w_index: int


@dataclass(frozen=True)
class SHA256ReverseCompressionTrace:
    """Working states recovered by reversing one SHA-256 compression block."""

    rounds: int
    initial_state: tuple[int, ...]
    output_state: tuple[int, ...]
    working_states: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class SHA256ForwardFeedTrace:
    """Feed-forward verification for a complete 64-byte prefix block plus suffix."""

    prefix_state: tuple[int, ...]
    padded_suffix_blocks: tuple[bytes, ...]
    digest: bytes
    verified_against_hashlib: bool


@dataclass(frozen=True)
class SHA256ScheduleNode:
    """One message-schedule word and its exact dependency names."""

    word_index: int
    operation: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class MajorityInversion:
    """Recovered majority-input bits and the mask of bits that remain ambiguous."""

    recovered_word: int
    determined_mask: int
    ambiguous_mask: int

    @property
    def fully_determined(self) -> bool:
        """Whether the unknown input is uniquely determined across all 32 bits."""
        return self.ambiguous_mask == 0


@dataclass(frozen=True)
class ChoiceOperandInversion:
    """Recovered bits for one unknown input to SHA-256's choice function."""

    recovered_word: int
    determined_mask: int
    ambiguous_mask: int

    @property
    def fully_determined(self) -> bool:
        """Whether this unknown input is uniquely determined across all bits."""
        return self.ambiguous_mask == 0


@dataclass(frozen=True)
class ChoiceInversion:
    """Per-input bit recovery for ``Ch(e, f, g)``."""

    e: ChoiceOperandInversion | None
    f: ChoiceOperandInversion | None
    g: ChoiceOperandInversion | None

    @property
    def fully_determined(self) -> bool:
        """Whether every omitted input operand is uniquely determined."""
        return all(
            operand is None or operand.fully_determined
            for operand in (self.e, self.f, self.g)
        )


def _ror(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK


def invert_majority_word(
    output: int,
    a: int | None,
    b: int | None,
    c: int | None,
) -> MajorityInversion:
    """Invert ``MAJ(a, b, c)`` for one unknown 32-bit operand.

    Bits where the two known operands agree are checked against the output,
    but the unknown operand is unconstrained there. Where they differ, the
    unknown operand bit equals the output bit.
    """
    operands = (a, b, c)
    if type(output) is not int or not 0 <= output <= _MASK:
        raise ValueError("output must be a 32-bit unsigned integer")
    if sum(value is None for value in operands) != 1:
        raise ValueError("exactly one majority input must be unknown")
    if any(
        value is not None and (type(value) is not int or not 0 <= value <= _MASK)
        for value in operands
    ):
        raise ValueError("known majority inputs must be 32-bit unsigned integers")

    known = tuple(value for value in operands if value is not None)
    assert len(known) == 2
    first, second = known
    equal_bits = ~(first ^ second) & _MASK
    if ((output ^ first) & equal_bits) != 0:
        raise ValueError("output conflicts with bits forced by the known inputs")

    determined_mask = first ^ second
    recovered_word = output & determined_mask
    return MajorityInversion(
        recovered_word,
        determined_mask,
        _MASK ^ determined_mask,
    )


def invert_choice_words(
    output: int,
    e: int | None,
    f: int | None,
    g: int | None,
) -> ChoiceInversion:
    """Invert the bitwise SHA-256 choice function for one or more unknown words.

    Enumerate the at most eight assignments to unknown operand bits in parallel
    across all 32 positions. An omitted input bit is reported as determined
    only when every satisfying completion gives it the same value.
    """
    operands = (e, f, g)
    if type(output) is not int or not 0 <= output <= _MASK:
        raise ValueError("output must be a 32-bit unsigned integer")
    if all(value is not None for value in operands):
        raise ValueError("at least one choice-function input must be unknown")
    if any(
        value is not None and (type(value) is not int or not 0 <= value <= _MASK)
        for value in operands
    ):
        raise ValueError("known choice-function inputs must be 32-bit unsigned integers")

    missing = tuple(index for index, value in enumerate(operands) if value is None)
    possible_zero = [0, 0, 0]
    possible_one = [0, 0, 0]
    satisfiable_mask = 0
    for candidate_bits in range(1 << len(missing)):
        values = list(operands)
        for unknown_index, operand_index in enumerate(missing):
            values[operand_index] = (
                _MASK if candidate_bits & (1 << unknown_index) else 0
            )
        e_word, f_word, g_word = values
        assert e_word is not None and f_word is not None and g_word is not None
        matches = ~(((e_word & f_word) | (~e_word & g_word)) ^ output) & _MASK
        satisfiable_mask |= matches
        for unknown_index, operand_index in enumerate(missing):
            if candidate_bits & (1 << unknown_index):
                possible_one[operand_index] |= matches
            else:
                possible_zero[operand_index] |= matches

    conflict_mask = _MASK ^ satisfiable_mask
    if conflict_mask:
        bit_index = (conflict_mask & -conflict_mask).bit_length() - 1
        raise ValueError(
            f"output conflicts with known choice-function inputs at bit {bit_index}"
        )

    recovered = tuple(
        None
        if value is not None
        else ChoiceOperandInversion(
            possible_one[index] & ~possible_zero[index] & _MASK,
            possible_zero[index] ^ possible_one[index],
            possible_zero[index] & possible_one[index],
        )
        for index, value in enumerate(operands)
    )
    return ChoiceInversion(*recovered)


def _rol(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK


def _sha_compress(block: bytes | memoryview, state: tuple[int, ...], rounds: int) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("SHA-256 compression block must be exactly 64 bytes")
    words = [
        int.from_bytes(block[index : index + 4], "big")
        for index in range(0, 64, 4)
    ]
    for index in range(16, rounds):
        x, y = words[index - 15], words[index - 2]
        sigma0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        sigma1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
        words.append((words[index - 16] + sigma0 + words[index - 7] + sigma1) & _MASK)
    a, b, c, d, e, f, g, h = state
    for index in range(rounds):
        upper_sigma1 = (
            ((e >> 6) | (e << 26))
            ^ ((e >> 11) | (e << 21))
            ^ ((e >> 25) | (e << 7))
        )
        choice = (e & f) ^ (~e & g)
        temp1 = (h + upper_sigma1 + choice + _SHA_K[index] + words[index]) & _MASK
        upper_sigma0 = (
            ((a >> 2) | (a << 30))
            ^ ((a >> 13) | (a << 19))
            ^ ((a >> 22) | (a << 10))
        )
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (upper_sigma0 + majority) & _MASK
        a, b, c, d, e, f, g, h = (temp1 + temp2) & _MASK, a, b, c, (d + temp1) & _MASK, e, f, g
    return tuple((old + new) & _MASK for old, new in zip(state, (a, b, c, d, e, f, g, h)))


def sha256_reduced(data: bytes, rounds: int = 32) -> bytes:
    """Hash with the SHA-256 structure but fewer rounds per block (1..64), for experiments only."""
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    if rounds == 64:
        return hashlib.sha256(data).digest()
    bit_length = len(data) * 8
    state = _SHA_IV
    complete_length = len(data) - len(data) % 64
    data_view = memoryview(data)
    for offset in range(0, complete_length, 64):
        state = _sha_compress(data_view[offset : offset + 64], state, rounds)
    tail = data[complete_length:] + b"\x80"
    tail += b"\0" * ((56 - len(tail) % 64) % 64)
    tail += bit_length.to_bytes(8, "big")
    for offset in range(0, len(tail), 64):
        state = _sha_compress(tail[offset : offset + 64], state, rounds)
    return b"".join(word.to_bytes(4, "big") for word in state)


def sha256_backward_trace(target_digest: bytes, rounds: int = 64) -> SHA256BackwardTrace:
    """Trace the numerically reversible A-word window from a one-block digest.

    The target must be the output of a SHA-256-shaped hash whose padded input
    occupies one block. This recovers at most four A words before reaching an
    unresolved E-state bridge; it does not recover a message or invert SHA-256.
    """
    if len(target_digest) != 32:
        raise ValueError("target_digest must be exactly 32 bytes")
    if not 8 <= rounds <= 64:
        raise ValueError("rounds must be between 8 and 64")

    digest_words = tuple(
        int.from_bytes(target_digest[index : index + 4], "big")
        for index in range(0, 32, 4)
    )
    working_state = tuple(
        (word - initial) & _MASK for word, initial in zip(digest_words, _SHA_IV)
    )
    a_values = {rounds - offset: working_state[offset] for offset in range(4)}
    e_values = {rounds - offset: working_state[4 + offset] for offset in range(4)}
    steps: list[SHA256BackwardStep] = []

    for round_index in range(rounds - 1, rounds - 5, -1):
        a, b, c = (
            a_values[round_index],
            a_values[round_index - 1],
            a_values[round_index - 2],
        )
        sigma0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (sigma0 + majority) & _MASK
        t1 = (a_values[round_index + 1] - t2) & _MASK
        recovered_a_index = round_index - 3
        recovered_a = (e_values[round_index + 1] - t1) & _MASK
        a_values[recovered_a_index] = recovered_a
        steps.append(
            SHA256BackwardStep(
                round_index=round_index,
                t1=t1,
                t2=t2,
                recovered_a_index=recovered_a_index,
                recovered_a=recovered_a,
            )
        )

    boundary_round = rounds - 5
    a, b, c = (
        a_values[boundary_round],
        a_values[boundary_round - 1],
        a_values[boundary_round - 2],
    )
    sigma0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
    majority = (a & b) ^ (a & c) ^ (b & c)
    boundary_t2 = (sigma0 + majority) & _MASK
    boundary_t1 = (a_values[boundary_round + 1] - boundary_t2) & _MASK
    last_round_t1 = steps[0].t1
    e_previous, f_previous, g_previous = working_state[5:8]
    sigma1 = _ror(e_previous, 6) ^ _ror(e_previous, 11) ^ _ror(e_previous, 25)
    choice = (e_previous & f_previous) ^ (~e_previous & g_previous)
    bridge_h_offset = (
        last_round_t1 - sigma1 - choice - _SHA_K[rounds - 1]
    ) & _MASK

    return SHA256BackwardTrace(
        working_state=working_state,
        known_a_values=tuple(sorted(a_values.items(), reverse=True)),
        steps=tuple(steps),
        boundary_round=boundary_round,
        boundary_a_index=boundary_round - 3,
        boundary_t1=boundary_t1,
        bridge_round=rounds - 1,
        bridge_h_index=rounds - 1,
        bridge_h_offset=bridge_h_offset,
        bridge_w_index=rounds - 1,
    )


def sha256_schedule_dependencies(rounds: int = 64) -> tuple[SHA256ScheduleNode, ...]:
    """Describe schedule dependencies consumed by the requested round count."""
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")

    nodes: list[SHA256ScheduleNode] = []
    for index in range(rounds):
        if index < 16:
            nodes.append(
                SHA256ScheduleNode(index, "input_word", (f"M{index}",))
            )
        else:
            nodes.append(
                SHA256ScheduleNode(
                    index,
                    "modular_sum",
                    (
                        f"sigma1(W{index - 2})",
                        f"W{index - 7}",
                        f"sigma0(W{index - 15})",
                        f"W{index - 16}",
                    ),
                )
            )
    return tuple(nodes)


def sha256_schedule_words(block: bytes) -> tuple[int, ...]:
    """Expand one 64-byte SHA-256 message block to its 64 schedule words."""
    if len(block) != 64:
        raise ValueError("SHA-256 schedule block must be exactly 64 bytes")
    words = [
        int.from_bytes(block[offset : offset + 4], "big")
        for offset in range(0, 64, 4)
    ]
    for index in range(16, 64):
        previous_15 = words[index - 15]
        previous_2 = words[index - 2]
        sigma0 = _ror(previous_15, 7) ^ _ror(previous_15, 18) ^ (previous_15 >> 3)
        sigma1 = _ror(previous_2, 17) ^ _ror(previous_2, 19) ^ (previous_2 >> 10)
        words.append(
            (words[index - 16] + sigma0 + words[index - 7] + sigma1) & _MASK
        )
    return tuple(words)


def sha256_reverse_compress(
    output_state: tuple[int, ...],
    block: bytes,
    *,
    rounds: int = 64,
    initial_state: tuple[int, ...] = _SHA_IV,
) -> SHA256ReverseCompressionTrace:
    """Reverse one compression block when its exact block and chaining state are known.

    The output state is the state after feed-forward. Since every message
    schedule word is known from the block, each round transition is invertible.
    A forward recomputation validates the supplied block and states first.
    This is a consistency tool, not a preimage attack.
    """
    if type(rounds) is not int or not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    if len(output_state) != 8 or len(initial_state) != 8:
        raise ValueError("output_state and initial_state must each contain eight words")
    if any(type(word) is not int or not 0 <= word <= _MASK for word in output_state + initial_state):
        raise ValueError("state words must be 32-bit unsigned integers")
    if len(block) != 64:
        raise ValueError("SHA-256 compression block must be exactly 64 bytes")
    if _sha_compress(block, initial_state, rounds) != output_state:
        raise ValueError("block and initial state do not compress to the supplied output state")

    schedule = sha256_schedule_words(block)
    working = tuple((word - initial) & _MASK for word, initial in zip(output_state, initial_state))
    reverse_states = [working]
    for index in range(rounds - 1, -1, -1):
        a1, b1, c1, d1, e1, f1, g1, h1 = working
        old_a, old_b, old_c = b1, c1, d1
        old_e, old_f, old_g = f1, g1, h1
        sigma0 = _ror(old_a, 2) ^ _ror(old_a, 13) ^ _ror(old_a, 22)
        majority = (old_a & old_b) ^ (old_a & old_c) ^ (old_b & old_c)
        t2 = (sigma0 + majority) & _MASK
        t1 = (a1 - t2) & _MASK
        old_d = (e1 - t1) & _MASK
        sigma1 = _ror(old_e, 6) ^ _ror(old_e, 11) ^ _ror(old_e, 25)
        choice = (old_e & old_f) ^ (~old_e & old_g)
        old_h = (t1 - sigma1 - choice - _SHA_K[index] - schedule[index]) & _MASK
        working = (old_a, old_b, old_c, old_d, old_e, old_f, old_g, old_h)
        reverse_states.append(working)

    if working != initial_state:
        raise ArithmeticError("reverse trace did not recover the supplied initial state")
    return SHA256ReverseCompressionTrace(
        rounds=rounds,
        initial_state=initial_state,
        output_state=output_state,
        working_states=tuple(reversed(reverse_states)),
    )


def sha256_forward_feed(prefix_block: bytes, suffix: bytes) -> SHA256ForwardFeedTrace:
    """Prepend one complete 512-bit block, continue SHA-256, and verify feed-forward.

    The first block is compressed from the SHA-256 IV without adding padding to
    it. The suffix is then padded using the total byte length (64 + len(suffix)).
    The internal compression result is checked against ``hashlib.sha256``.
    """
    if len(prefix_block) != 64:
        raise ValueError("prefix_block must be exactly 64 bytes (512 bits)")
    total_length = 64 + len(suffix)
    if total_length > _SHA256_MAX_BYTES:
        raise ValueError("message exceeds the SHA-256 64-bit length limit")
    prefix_state = _sha_compress(prefix_block, _SHA_IV, 64)
    tail = suffix + b"\x80"
    tail += b"\0" * ((56 - len(tail) % 64) % 64)
    tail += (total_length * 8).to_bytes(8, "big")
    blocks = tuple(tail[offset : offset + 64] for offset in range(0, len(tail), 64))
    final_state = prefix_state
    for block in blocks:
        final_state = _sha_compress(block, final_state, 64)
    digest = b"".join(word.to_bytes(4, "big") for word in final_state)
    reference = hashlib.sha256(prefix_block + suffix).digest()
    if digest != reference:
        raise ArithmeticError("SHA-256 forward-feed result disagrees with hashlib")
    return SHA256ForwardFeedTrace(prefix_state, blocks, digest, True)


def _byte_chunks(source: BinaryIO | Iterable[bytes]) -> Iterator[bytes]:
    reader = getattr(source, "read", None)
    if callable(reader):
        while True:
            chunk = reader(_STREAM_READ_SIZE)
            if chunk == b"":
                break
            if not isinstance(chunk, bytes):
                raise TypeError("binary stream must return bytes")
            yield chunk
        return

    for chunk in source:
        if not isinstance(chunk, bytes):
            raise TypeError("input chunks must be bytes")
        yield chunk


def sha256_reduced_stream(source: BinaryIO | Iterable[bytes], rounds: int = 32) -> bytes:
    """Hash a binary stream or iterable of byte chunks without buffering all input.

    At 64 rounds this delegates to the platform's optimized SHA-256 implementation.
    Reduced-round mode uses a bounded carry buffer, processes complete 64-byte blocks
    as they arrive, and pads once at end of stream.
    """
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")

    if rounds == 64:
        digest = hashlib.sha256()
        total_length = 0
        for chunk in _byte_chunks(source):
            total_length += len(chunk)
            if total_length > _SHA256_MAX_BYTES:
                raise ValueError("input length exceeds the SHA-256 64-bit bit-length field")
            digest.update(chunk)
        return digest.digest()

    state = _SHA_IV
    pending = bytearray()
    total_length = 0
    for chunk in _byte_chunks(source):
        total_length += len(chunk)
        if total_length > _SHA256_MAX_BYTES:
            raise ValueError("input length exceeds the SHA-256 64-bit bit-length field")
        chunk_view = memoryview(chunk)
        offset = 0

        if pending:
            needed = 64 - len(pending)
            take = min(needed, len(chunk_view))
            pending.extend(chunk_view[:take])
            offset += take
            if len(pending) == 64:
                state = _sha_compress(bytes(pending), state, rounds)
                pending.clear()

        complete_end = offset + ((len(chunk_view) - offset) // 64) * 64
        while offset < complete_end:
            state = _sha_compress(chunk_view[offset : offset + 64], state, rounds)
            offset += 64
        if offset < len(chunk_view):
            pending.extend(chunk_view[offset:])

    tail = bytes(pending) + b"\x80"
    tail += b"\0" * ((56 - len(tail) % 64) % 64)
    tail += (total_length * 8).to_bytes(8, "big")
    for offset in range(0, len(tail), 64):
        state = _sha_compress(tail[offset : offset + 64], state, rounds)
    return b"".join(word.to_bytes(4, "big") for word in state)


_R1 = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
_R2 = (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
_S1 = (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
_S2 = (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
_K1 = (0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_K2 = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0)


def _ripemd_f(index: int, x: int, y: int, z: int) -> int:
    if index == 0:
        return x ^ y ^ z
    if index == 1:
        return (x & y) | (~x & z)
    if index == 2:
        return (x | ~y) ^ z
    if index == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160_reduced(data: bytes, steps: int = 80) -> bytes:
    """Compute RIPEMD-160-style digest with 1..80 steps in both parallel branches."""
    if not 1 <= steps <= 80:
        raise ValueError("steps must be between 1 and 80")
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\0" * ((56 - len(padded) % 64) % 64)
    padded += bit_length.to_bytes(8, "little")
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        words = [int.from_bytes(block[index : index + 4], "little") for index in range(0, 64, 4)]
        al, bl, cl, dl, el = state
        ar, br, cr, dr, er = state
        for index in range(steps):
            round_index = index // 16
            left = (_ror((al + _ripemd_f(round_index, bl, cl, dl) + words[_R1[index]] + _K1[round_index]) & _MASK, 32 - _S1[index]) + el) & _MASK
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, left
            right_round = 4 - round_index
            right = (_ror((ar + _ripemd_f(right_round, br, cr, dr) + words[_R2[index]] + _K2[round_index]) & _MASK, 32 - _S2[index]) + er) & _MASK
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, right
        temporary = (state[1] + cl + dr) & _MASK
        state[1] = (state[2] + dl + er) & _MASK
        state[2] = (state[3] + el + ar) & _MASK
        state[3] = (state[4] + al + br) & _MASK
        state[4] = (state[0] + bl + cr) & _MASK
        state[0] = temporary
    return b"".join(word.to_bytes(4, "little") for word in state)


def ripemd160(data: bytes) -> bytes:
    """Compute standard 80-step RIPEMD-160."""
    return ripemd160_reduced(data, steps=80)


def ripemd160_matches_hashlib(data: bytes) -> bool:
    """Compare the reference implementation to hashlib when the provider is available."""
    try:
        expected = hashlib.new("ripemd160", data).digest()
    except ValueError:
        return False
    return ripemd160(data) == expected
