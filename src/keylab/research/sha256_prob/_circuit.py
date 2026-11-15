"""Bit-level boolean circuit for the reduced-round SHA-256 compression.

This is the shared substrate for Phase C: both the belief-propagation factor graph
(:mod:`keylab.research.sha256_prob.belief_propagation`) and the MILP emitter
(:mod:`keylab.research.sha256_prob.sha256_milp`) are built by walking the same
circuit, so they model *exactly* the same function. The circuit is validated
against :func:`keylab.hashes.reduced.sha256_reduced`'s compression in the tests.

Every wire is a binary variable. Only four gate primitives are used, each with
small fan-in so the derived factors/constraints stay tiny:

- ``const``: a wire pinned to 0 or 1 (IV and round-constant bits, fixed message bits);
- ``input``: a free message bit, tagged by ``(word, bit)``;
- ``xor``: XOR of up to three wires (the Sigma/sigma mixers and full-adder sums);
- ``maj`` / ``ch``: the SHA-256 majority and choice bits (also the adder carry = maj).

Modular addition is a ripple of full adders: ``sum = a^b^cin`` (an ``xor``) and
``carry = maj(a, b, cin)`` (a ``maj``), with the final carry dropped (mod 2**32).
Rotations and shifts are pure rewiring (no gate). Gates are emitted in topological
order, so a single forward pass evaluates the whole circuit.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.hashes.reduced import _SHA_IV, _SHA_K

_MASK = 0xFFFFFFFF
_WORD_BITS = 32

# A gate is (kind, output_var, inputs). For "const" inputs is (value,); for
# "input" it is (word, bit); for xor/maj/ch it is a tuple of input var ids.
Gate = tuple[str, int, tuple[int, ...]]


@dataclass
class Circuit:
    """A finished reduced-round compression circuit over binary wires."""

    rounds: int
    num_vars: int
    gates: tuple[Gate, ...]
    input_bits: tuple[tuple[int, int, int], ...]  # (var, word, bit) for each free input
    output_words: tuple[tuple[int, ...], ...]      # 8 words, each 32 var ids (LSB first)
    const_zero: int

    def input_map(self) -> dict[tuple[int, int], int]:
        """Map ``(word, bit) -> var id`` for every free input bit."""
        return {(word, bit): var for var, word, bit in self.input_bits}

    def evaluate(self, assignment: dict[int, int]) -> list[int]:
        """Evaluate all gates given free-input var assignments; return 8 output words.

        ``assignment`` maps each free-input var id to 0/1. Any free input left out
        defaults to 0. Returns the eight 32-bit output words (feed-forward applied).
        """
        value = [0] * self.num_vars
        for kind, out, data in self.gates:
            if kind == "const":
                value[out] = data[0]
            elif kind == "input":
                value[out] = assignment.get(out, 0) & 1
            elif kind == "xor":
                acc = 0
                for src in data:
                    acc ^= value[src]
                value[out] = acc
            elif kind == "maj":
                a, b, c = (value[s] for s in data)
                value[out] = 1 if (a + b + c) >= 2 else 0
            elif kind == "ch":
                e, f, g = (value[s] for s in data)
                value[out] = f if e else g
            else:  # pragma: no cover - defensive
                raise ValueError(f"unknown gate kind {kind!r}")
        words = []
        for word_bits in self.output_words:
            acc = 0
            for bit, var in enumerate(word_bits):
                acc |= value[var] << bit
            words.append(acc)
        return words


class _Builder:
    """Accumulates gates while constructing the circuit in topological order."""

    def __init__(self) -> None:
        self.gates: list[Gate] = []
        self._count = 0
        self.const_zero = self._emit_const(0)
        self.const_one = self._emit_const(1)
        self.input_bits: list[tuple[int, int, int]] = []

    def _new(self) -> int:
        var = self._count
        self._count += 1
        return var

    def _emit_const(self, value: int) -> int:
        var = self._new()
        self.gates.append(("const", var, (value & 1,)))
        return var

    def const_bit(self, value: int) -> int:
        return self.const_one if value & 1 else self.const_zero

    def input_bit(self, word: int, bit: int) -> int:
        var = self._new()
        self.gates.append(("input", var, (word, bit)))
        self.input_bits.append((var, word, bit))
        return var

    def xor(self, *inputs: int) -> int:
        if not 1 <= len(inputs) <= 3:
            raise ValueError("xor fan-in must be 1..3")
        var = self._new()
        self.gates.append(("xor", var, tuple(inputs)))
        return var

    def maj(self, a: int, b: int, c: int) -> int:
        var = self._new()
        self.gates.append(("maj", var, (a, b, c)))
        return var

    def ch(self, e: int, f: int, g: int) -> int:
        var = self._new()
        self.gates.append(("ch", var, (e, f, g)))
        return var

    # --- word-level helpers (a "word" is a list of 32 var ids, LSB first) ---

    def word_const(self, value: int) -> list[int]:
        return [self.const_bit((value >> bit) & 1) for bit in range(_WORD_BITS)]

    def rotr(self, word: list[int], count: int) -> list[int]:
        return [word[(bit + count) % _WORD_BITS] for bit in range(_WORD_BITS)]

    def shr(self, word: list[int], count: int) -> list[int]:
        return [word[bit + count] if bit + count < _WORD_BITS else self.const_zero
                for bit in range(_WORD_BITS)]

    def xor_words(self, *words: list[int]) -> list[int]:
        return [self.xor(*(word[bit] for word in words)) for bit in range(_WORD_BITS)]

    def add_words(self, first: list[int], second: list[int]) -> list[int]:
        carry = self.const_zero
        out: list[int] = []
        for bit in range(_WORD_BITS):
            a, b = first[bit], second[bit]
            out.append(self.xor(a, b, carry))
            carry = self.maj(a, b, carry)  # carry-out of a full adder is maj(a, b, cin)
        return out  # final carry dropped => mod 2**32

    def add_many(self, *words: list[int]) -> list[int]:
        total = words[0]
        for word in words[1:]:
            total = self.add_words(total, word)
        return total

    def maj_words(self, a: list[int], b: list[int], c: list[int]) -> list[int]:
        return [self.maj(a[bit], b[bit], c[bit]) for bit in range(_WORD_BITS)]

    def ch_words(self, e: list[int], f: list[int], g: list[int]) -> list[int]:
        return [self.ch(e[bit], f[bit], g[bit]) for bit in range(_WORD_BITS)]

    def big_sigma0(self, word: list[int]) -> list[int]:
        return self.xor_words(self.rotr(word, 2), self.rotr(word, 13), self.rotr(word, 22))

    def big_sigma1(self, word: list[int]) -> list[int]:
        return self.xor_words(self.rotr(word, 6), self.rotr(word, 11), self.rotr(word, 25))

    def small_sigma0(self, word: list[int]) -> list[int]:
        return self.xor_words(self.rotr(word, 7), self.rotr(word, 18), self.shr(word, 3))

    def small_sigma1(self, word: list[int]) -> list[int]:
        return self.xor_words(self.rotr(word, 17), self.rotr(word, 19), self.shr(word, 10))


def build_compression_circuit(rounds: int, *, free_input_bits: int = 512) -> Circuit:
    """Build the ``rounds``-round compression circuit from the SHA-256 IV.

    ``free_input_bits`` free message bits (taken LSB-first across words 0..15) are
    ``input`` wires; the remaining message bits are pinned to 0. This matches
    :func:`keylab.hashes.reduced.sha256_reduced` compressing a single 64-byte block
    (whose unset bits are 0) from the IV for ``rounds`` rounds, with feed-forward.
    """
    if type(rounds) is not int or not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    if type(free_input_bits) is not int or not 0 <= free_input_bits <= 512:
        raise ValueError("free_input_bits must be between 0 and 512")

    builder = _Builder()
    iv_words = [builder.word_const(value) for value in _SHA_IV]

    # Message words 0..15, each bit a free input (while the budget lasts) or const 0.
    # Free bits are allocated big-endian by (word, bit-from-MSB) so the first free
    # bits correspond to the most significant message bits (the bytes that vary first).
    schedule: list[list[int]] = []
    freed = 0
    for word in range(16):
        bits: list[int] = []
        for bit in range(_WORD_BITS):
            msb_index = word * _WORD_BITS + (_WORD_BITS - 1 - bit)
            if msb_index < free_input_bits:
                bits.append(builder.input_bit(word, bit))
                freed += 1
            else:
                bits.append(builder.const_zero)
        schedule.append(bits)
    assert freed == free_input_bits

    for index in range(16, rounds):
        schedule.append(builder.add_many(
            schedule[index - 16],
            builder.small_sigma0(schedule[index - 15]),
            schedule[index - 7],
            builder.small_sigma1(schedule[index - 2]),
        ))

    a, b, c, d, e, f, g, h = (list(word) for word in iv_words)
    for index in range(rounds):
        t1 = builder.add_many(
            h, builder.big_sigma1(e), builder.ch_words(e, f, g),
            builder.word_const(_SHA_K[index]), schedule[index],
        )
        t2 = builder.add_words(builder.big_sigma0(a), builder.maj_words(a, b, c))
        new_a = builder.add_words(t1, t2)
        new_e = builder.add_words(d, t1)
        a, b, c, d, e, f, g, h = new_a, a, b, c, new_e, e, f, g

    final = (a, b, c, d, e, f, g, h)
    output_words = tuple(tuple(builder.add_words(iv_words[k], final[k])) for k in range(8))

    return Circuit(
        rounds=rounds,
        num_vars=builder._count,
        gates=tuple(builder.gates),
        input_bits=tuple(builder.input_bits),
        output_words=output_words,
        const_zero=builder.const_zero,
    )
