"""LSB-leak interval-shrink halving attack: exact recovery, forward-verified."""

from __future__ import annotations

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.halving_lsb import demo_instance, lsb_halving_attack


@pytest.mark.parametrize("secret", [0xBEEF, 0xC0FFEE, 1, 2, 0xDEADBE])
def test_full_leak_recovers_scalar(secret: int) -> None:
    public_key = scalar_mult(secret, G)
    lsbs = [(secret >> i) & 1 for i in range(secret.bit_length())]
    result = lsb_halving_attack(public_key, lsbs, interval=(0, (1 << secret.bit_length()) - 1))
    assert result.recovered_scalar == secret
    assert result.verified is True
    assert result.low_bits_value == secret
    assert len(result.steps) == secret.bit_length()


def test_partial_leak_shrinks_then_sweeps() -> None:
    secret = 0xABCDEF  # 24 bits
    leaked = 12
    public_key = scalar_mult(secret, G)
    lsbs = [(secret >> i) & 1 for i in range(leaked)]
    result = lsb_halving_attack(public_key, lsbs, interval=(0, (1 << 24) - 1))
    assert result.recovered_scalar == secret
    assert result.verified is True
    assert result.leaked_bits == leaked
    assert result.low_bits_value == (secret & ((1 << leaked) - 1))
    assert result.high_window_width == (1 << (24 - leaked))


def test_demo_instance_recovers() -> None:
    summary = demo_instance(0xC0FFEE, 12)
    assert summary["recovered_matches_secret"] is True
    assert summary["verified"] is True


def test_rejects_non_binary_leak() -> None:
    public_key = scalar_mult(5, G)
    with pytest.raises(ValueError, match="0 or 1"):
        lsb_halving_attack(public_key, [0, 2, 1])


def test_rejects_bad_interval() -> None:
    public_key = scalar_mult(5, G)
    with pytest.raises(ValueError, match="interval"):
        lsb_halving_attack(public_key, [1], interval=(10, 5))
    with pytest.raises(ValueError, match="interval"):
        lsb_halving_attack(public_key, [1], interval=(0, N))


def test_rejects_oversized_high_window() -> None:
    secret = 0xABCDEF
    public_key = scalar_mult(secret, G)
    # Leak nothing useful but keep a huge interval -> residual window too large.
    with pytest.raises(ValueError, match="high window"):
        lsb_halving_attack(public_key, [secret & 1], interval=(0, (1 << 40) - 1), max_high_window=1024)


def test_demo_validates_arguments() -> None:
    with pytest.raises(ValueError, match="secret"):
        demo_instance(0)
    with pytest.raises(ValueError, match="leaked_bits"):
        demo_instance(0xFF, 99)
