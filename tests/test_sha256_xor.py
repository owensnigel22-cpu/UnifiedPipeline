"""SHA-256 Sigma/sigma rotations emitted as native XOR rows, solved by CryptoMiniSat.

Each gadget is checked bit-exact against an independent Python reference for the
four rotation functions, routed through the native-XOR solver path.
"""

from __future__ import annotations

import random

import pytest

from keylab.hashes import sha256_xor
from keylab.sat.backends import solve_xor_formula
from keylab.sat.cryptominisat import CryptoMiniSatFormula

_MASK = 0xFFFFFFFF


def _rotr(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & _MASK


def _shr(value: int, amount: int) -> int:
    return (value >> amount) & _MASK


def _ref_small_sigma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _ref_small_sigma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def _ref_big_sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _ref_big_sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


_GADGETS = {
    "small_sigma0": (sha256_xor.small_sigma0, _ref_small_sigma0),
    "small_sigma1": (sha256_xor.small_sigma1, _ref_small_sigma1),
    "big_sigma0": (sha256_xor.big_sigma0, _ref_big_sigma0),
    "big_sigma1": (sha256_xor.big_sigma1, _ref_big_sigma1),
}

_VALUES = [0x00000000, 0xFFFFFFFF, 0x00000001, 0x80000000, 0xDEADBEEF, 0x243F6A88]
_VALUES += [random.Random(seed).getrandbits(32) for seed in range(6)]


@pytest.mark.parametrize("name", sorted(_GADGETS))
@pytest.mark.parametrize("value", _VALUES)
def test_sigma_gadget_matches_reference(name: str, value: int) -> None:
    gadget, reference = _GADGETS[name]
    formula = CryptoMiniSatFormula()
    word = sha256_xor.allocate_word(formula)
    output = gadget(formula, word)
    sha256_xor.fix_word(formula, word, value)

    # The linear layer must be carried as native XOR rows, not CNF clauses.
    assert formula.xors, "gadget emitted no native XOR rows"

    result = solve_xor_formula(formula)
    assert result.status == "SATISFIABLE"
    assert result.backend == "cryptosat-xor"
    assert sha256_xor.decode_word(result.assignments, output) == reference(value)


def test_word_helpers_round_trip() -> None:
    formula = CryptoMiniSatFormula()
    word = sha256_xor.allocate_word(formula)
    assert len(word) == 32
    sha256_xor.fix_word(formula, word, 0xCAFEBABE)
    result = solve_xor_formula(formula)
    assert result.status == "SATISFIABLE"
    assert sha256_xor.decode_word(result.assignments, word) == 0xCAFEBABE


def test_fix_word_rejects_out_of_range() -> None:
    formula = CryptoMiniSatFormula()
    word = sha256_xor.allocate_word(formula)
    with pytest.raises(ValueError, match="32-bit"):
        sha256_xor.fix_word(formula, word, 1 << 32)


def test_empty_true_xor_is_unsat() -> None:
    formula = CryptoMiniSatFormula(variable_count=1)
    formula.xors.append(((), True))  # XOR()=true is a contradiction
    assert solve_xor_formula(formula).status == "UNSATISFIABLE"
