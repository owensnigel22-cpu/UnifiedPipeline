"""Demonstrate rogue keys against naive and BIP-327 key aggregation."""

from __future__ import annotations

import pytest

from keylab.ec.musig2 import key_agg
from keylab.ec.secp256k1 import (
    G,
    compress_pubkey,
    point_add_affine,
    point_negate_affine,
    scalar_mult,
)
from keylab.research.cryptanalysis.musig2_rogue_key import demonstrate_rogue_key_resistance


def test_naive_aggregation_is_rogue_key_vulnerable_but_bip327_is_not() -> None:
    result = demonstrate_rogue_key_resistance(
        honest_secret=12_345,
        attacker_target_secret=67_890,
    )
    assert result.naive_attack_succeeds is True
    assert result.naive_aggregate == result.rogue_target
    assert result.musig2_aggregate_matches_target_xonly is False

    # Cross-check the demonstration against the repository's BIP-327 KeyAgg.
    honest = scalar_mult(12_345, G)
    rogue = point_add_affine(
        scalar_mult(67_890, G), point_negate_affine(honest),
    )
    assert rogue is not None
    context = key_agg([compress_pubkey(honest), compress_pubkey(rogue)])
    assert context == result.musig2_context


@pytest.mark.parametrize("secret", [0, -1, 1 << 256])
def test_rogue_key_demo_validates_private_scalar_inputs(secret: int) -> None:
    with pytest.raises(ValueError, match=r"\[1, N-1\]"):
        demonstrate_rogue_key_resistance(secret, 2)
