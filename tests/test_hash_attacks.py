"""Truncated SHA-256 pre-image + length extension (educational).

Every result is checked against an INDEPENDENT recompute: a found pre-image's
digest is re-hashed and its prefix compared; a forged length-extension digest is
compared to hashlib.sha256(secret || forged_message). Heavy brute-forcing is
marked @slow (deselected by default). The full 256-bit pre-image is never
attempted -- bits is hard-capped at 40.
"""

from __future__ import annotations

import hashlib

import pytest

from keylab.hashes.reduced import sha256_reduced
from keylab.research.hash_attacks import (
    MAX_BITS,
    demonstrate_length_extension,
    find_truncated_preimage,
    truncated_prefix,
)

_TARGET = hashlib.sha256(b"m5 target message").digest()


# --- truncated pre-image (fast, always-run) -----------------------------------------------------

@pytest.mark.parametrize("bits", [8, 12, 16])
def test_finds_truncated_preimage_forward_verified(bits) -> None:
    result = find_truncated_preimage(_TARGET, bits=bits)
    assert result is not None
    # independent recompute: the found message's digest matches the target prefix
    assert truncated_prefix(hashlib.sha256(result.message).digest(), bits) == truncated_prefix(_TARGET, bits)
    assert 1 <= result.tries


def test_reduced_round_preimage() -> None:
    target = sha256_reduced(b"reduced target", 32)
    result = find_truncated_preimage(target, bits=12, rounds=32)
    assert result is not None
    assert truncated_prefix(sha256_reduced(result.message, 32), 12) == truncated_prefix(target, 12)


def test_bits_cap_and_validation() -> None:
    with pytest.raises(ValueError, match="hard cap"):
        find_truncated_preimage(_TARGET, bits=MAX_BITS + 1)   # above 40 -> refused
    with pytest.raises(ValueError, match="hard cap"):
        find_truncated_preimage(_TARGET, bits=0)
    with pytest.raises(ValueError, match="bits"):
        find_truncated_preimage(_TARGET, bits=2.0)            # type: ignore[arg-type]
    with pytest.raises(ValueError, match="rounds"):
        find_truncated_preimage(_TARGET, bits=8, rounds=99)
    with pytest.raises(ValueError, match="target"):
        find_truncated_preimage(b"\x00", bits=16)             # too few bits in target


def test_returns_none_within_tiny_budget() -> None:
    # 16-bit match within only 3 tries is overwhelmingly unlikely -> None.
    assert find_truncated_preimage(_TARGET, bits=16, max_tries=3) is None


def test_parallel_workers_find_equivalent_result() -> None:
    # workers>1 must find a forward-verified pre-image for the same target.
    result = find_truncated_preimage(_TARGET, bits=12, workers=2)
    assert result is not None
    assert truncated_prefix(hashlib.sha256(result.message).digest(), 12) == truncated_prefix(_TARGET, 12)


@pytest.mark.slow
def test_slow_24_bit_preimage() -> None:
    # ~2**24 hashes; opt-in (run with -m slow). The honest cost of a 24-bit prefix.
    result = find_truncated_preimage(_TARGET, bits=24)
    assert result is not None
    assert truncated_prefix(hashlib.sha256(result.message).digest(), 24) == truncated_prefix(_TARGET, 24)


# --- length extension (fast, always-run) --------------------------------------------------------

def test_length_extension_forges_valid_digest() -> None:
    secret = b"super-secret-key-1234"
    message = b"amount=100&to=alice"
    original = hashlib.sha256(secret + message).digest()  # H(secret || message)
    extension = b"&to=mallory"

    report = demonstrate_length_extension(original, message, len(secret), extension)
    assert report.secret_used is False
    # INDEPENDENT check: the real hash of (secret || forged_message) equals the forged digest
    assert hashlib.sha256(secret + report.forged_message).digest() == report.forged_digest
    # the forge actually appended the attacker's extension
    assert report.forged_message.startswith(message)
    assert report.forged_message.endswith(extension)


def test_length_extension_rejects_bad_extension() -> None:
    original = hashlib.sha256(b"x").digest()
    with pytest.raises(TypeError):
        demonstrate_length_extension(original, b"m", 1, "not bytes")  # type: ignore[arg-type]
