"""SHA-256 Sigma/sigma rotations emitted as native CryptoMiniSat XOR rows.

The SHA-256 message schedule and round function mix a *linear* layer (the
``Sigma0/Sigma1`` big-sigma and ``sigma0/sigma1`` small-sigma rotate/shift-xor
functions, each output bit a 2- or 3-input XOR of input bits) with a *nonlinear*
layer (modular additions, ``Ch``, ``Maj``). A CNF-only solver must Tseitin-expand
every XOR into clauses and fresh variables; CryptoMiniSat can carry the linear
layer as native XOR rows (``x a b c 0``) instead.

This module builds the four rotation functions directly onto a
:class:`~keylab.sat.cryptominisat.CryptoMiniSatFormula` as native XOR rows, so a
reduced-round model can hand its linear layer to CryptoMiniSat's XOR engine
(:func:`keylab.sat.backends.solve_xor_formula`). The gadgets are bit-exact with
the SHA-256 specification and are validated against an independent reference.

Scope: these are reusable linear-layer gadgets for bounded, reduced-round
research models. Nothing here attacks full 64-round SHA-256.
"""

from __future__ import annotations

from keylab.sat.cryptominisat import CryptoMiniSatFormula

XorWord = tuple[int, ...]

_WORD_BITS = 32


def allocate_word(formula: CryptoMiniSatFormula) -> XorWord:
    """Allocate 32 fresh variables for one word, least-significant bit first."""
    base = formula.variable_count
    formula.variable_count = base + _WORD_BITS
    return tuple(range(base + 1, base + 1 + _WORD_BITS))


def fix_word(formula: CryptoMiniSatFormula, word: XorWord, value: int) -> None:
    """Constrain ``word`` (LSB first) to the 32-bit ``value`` with unit clauses."""
    if len(word) != _WORD_BITS:
        raise ValueError("word must have exactly 32 bits")
    if type(value) is not int or not 0 <= value < (1 << _WORD_BITS):
        raise ValueError("value must be a 32-bit unsigned integer")
    for bit, variable in enumerate(word):
        set_bit = (value >> bit) & 1
        formula.add_clause((variable if set_bit else -variable,))


def decode_word(assignment: dict[int, bool], word: XorWord) -> int:
    """Read a 32-bit value from a solver assignment (missing bits read as 0)."""
    value = 0
    for bit, variable in enumerate(word):
        if assignment.get(variable, False):
            value |= 1 << bit
    return value


def _rotr_bit(word: XorWord, output_bit: int, amount: int) -> int:
    """Input variable feeding ``output_bit`` of a right-rotation by ``amount``."""
    return word[(output_bit + amount) % _WORD_BITS]


def _shr_bit(word: XorWord, output_bit: int, amount: int) -> int | None:
    """Input variable feeding ``output_bit`` of a right-shift, or None for a 0 bit."""
    source = output_bit + amount
    return word[source] if source < _WORD_BITS else None


def _emit_xor_word(
    formula: CryptoMiniSatFormula,
    contributors: list[list[int]],
) -> XorWord:
    """Allocate an output word and tie each bit to the XOR of its contributors."""
    output = allocate_word(formula)
    for output_bit, inputs in enumerate(contributors):
        # output_bit XOR inputs == 0, i.e. output_bit == XOR(inputs).
        formula.add_xor([output[output_bit], *inputs], rhs=False)
    return output


def small_sigma0(formula: CryptoMiniSatFormula, word: XorWord) -> XorWord:
    """Emit sigma0(x) = ROTR7(x) ^ ROTR18(x) ^ SHR3(x) as native XOR rows."""
    contributors = []
    for output_bit in range(_WORD_BITS):
        bits = [_rotr_bit(word, output_bit, 7), _rotr_bit(word, output_bit, 18)]
        shifted = _shr_bit(word, output_bit, 3)
        if shifted is not None:
            bits.append(shifted)
        contributors.append(bits)
    return _emit_xor_word(formula, contributors)


def small_sigma1(formula: CryptoMiniSatFormula, word: XorWord) -> XorWord:
    """Emit sigma1(x) = ROTR17(x) ^ ROTR19(x) ^ SHR10(x) as native XOR rows."""
    contributors = []
    for output_bit in range(_WORD_BITS):
        bits = [_rotr_bit(word, output_bit, 17), _rotr_bit(word, output_bit, 19)]
        shifted = _shr_bit(word, output_bit, 10)
        if shifted is not None:
            bits.append(shifted)
        contributors.append(bits)
    return _emit_xor_word(formula, contributors)


def big_sigma0(formula: CryptoMiniSatFormula, word: XorWord) -> XorWord:
    """Emit Sigma0(x) = ROTR2(x) ^ ROTR13(x) ^ ROTR22(x) as native XOR rows."""
    contributors = [
        [_rotr_bit(word, output_bit, 2), _rotr_bit(word, output_bit, 13), _rotr_bit(word, output_bit, 22)]
        for output_bit in range(_WORD_BITS)
    ]
    return _emit_xor_word(formula, contributors)


def big_sigma1(formula: CryptoMiniSatFormula, word: XorWord) -> XorWord:
    """Emit Sigma1(x) = ROTR6(x) ^ ROTR11(x) ^ ROTR25(x) as native XOR rows."""
    contributors = [
        [_rotr_bit(word, output_bit, 6), _rotr_bit(word, output_bit, 11), _rotr_bit(word, output_bit, 25)]
        for output_bit in range(_WORD_BITS)
    ]
    return _emit_xor_word(formula, contributors)


__all__ = [
    "XorWord",
    "allocate_word",
    "big_sigma0",
    "big_sigma1",
    "decode_word",
    "fix_word",
    "small_sigma0",
    "small_sigma1",
]
