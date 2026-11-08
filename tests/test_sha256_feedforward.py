"""Tests for direct SHA-256 feed-forward subtraction."""

from __future__ import annotations

import hashlib

import pytest

from keylab.hashes.reduced import _sha_compress, sha256_reverse_compress
from keylab.research.cryptanalysis.sha256_feedforward import SHA256_IV, unwind_feed_forward


def test_abc_digest_unwinds_to_the_actual_pre_feedforward_state() -> None:
    message = b"abc"
    padded = message + b"\x80" + b"\x00" * (56 - len(message) - 1) + (len(message) * 8).to_bytes(8, "big")
    digest = hashlib.sha256(message).digest()
    compressed = _sha_compress(padded, SHA256_IV, rounds=64)
    trace = sha256_reverse_compress(compressed, padded, rounds=64, initial_state=SHA256_IV)

    recovered = unwind_feed_forward(digest, SHA256_IV)
    assert recovered == trace.working_states[-1]
    assert tuple((word + iv) & 0xFFFFFFFF for word, iv in zip(recovered, SHA256_IV)) == tuple(compressed)


def test_feedforward_accepts_word_sequences_and_rejects_bad_shapes() -> None:
    words = (0xFFFFFFFF, 0, 1, 2, 3, 4, 5, 6)
    iv = (1, 2, 3, 4, 5, 6, 7, 8)
    assert unwind_feed_forward(words, iv) == (0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE,
                                               0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE)
    with pytest.raises(ValueError, match="32 bytes"):
        unwind_feed_forward(b"short")
    with pytest.raises(ValueError, match="eight"):
        unwind_feed_forward((0,) * 7)
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        unwind_feed_forward((0,) * 7 + (1 << 32,))
