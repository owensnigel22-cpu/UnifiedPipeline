"""The shared Phase C bit circuit must equal the reference reduced compression."""

from __future__ import annotations

import secrets

import pytest

from keylab.hashes.reduced import _SHA_IV, _sha_compress
from keylab.research.sha256_prob._circuit import build_compression_circuit


def _block_assignment(circuit, block: bytes) -> dict[int, int]:
    words = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
    return {var: (words[word] >> bit) & 1 for (word, bit), var in circuit.input_map().items()}


@pytest.mark.parametrize("rounds", [1, 2, 3, 8, 16, 17, 20])
def test_circuit_matches_reference_compression(rounds: int) -> None:
    circuit = build_compression_circuit(rounds, free_input_bits=512)
    assert len(circuit.input_bits) == 512
    for _ in range(4):
        block = secrets.token_bytes(64)
        expected = list(_sha_compress(block, _SHA_IV, rounds))
        got = circuit.evaluate(_block_assignment(circuit, block))
        assert got == expected


def test_partial_free_bits_pins_the_rest_to_zero() -> None:
    circuit = build_compression_circuit(2, free_input_bits=40)
    assert len(circuit.input_bits) == 40
    # Free bits are the 40 most-significant message bits: all of word 0, top byte of word 1.
    message = bytearray(64)
    message[0:4] = b"\xab\xcd\xef\x12"
    message[4] = 0x80
    expected = list(_sha_compress(bytes(message), _SHA_IV, 2))
    got = circuit.evaluate(_block_assignment(circuit, bytes(message)))
    assert got == expected


def test_build_validates_arguments() -> None:
    with pytest.raises(ValueError, match="rounds"):
        build_compression_circuit(0)
    with pytest.raises(ValueError, match="rounds"):
        build_compression_circuit(65)
    with pytest.raises(ValueError, match="free_input_bits"):
        build_compression_circuit(4, free_input_bits=513)
