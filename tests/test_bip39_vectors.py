"""Official BIP-39 seed vectors (Trezor reference set, English, passphrase "TREZOR")."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keylab.hd import ExtendedKey, mnemonic_to_seed

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "bip39_trezor_vectors.json").read_text(encoding="utf-8")
)


def test_fixture_contains_all_english_vectors() -> None:
    assert VECTORS["passphrase"] == "TREZOR"
    assert len(VECTORS["english"]) == 24


@pytest.mark.parametrize("entropy,mnemonic,seed,xprv", VECTORS["english"], ids=lambda v: v[:12])
def test_bip39_seed_and_bip32_root_match_official_vector(entropy: str, mnemonic: str,
                                                         seed: str, xprv: str) -> None:
    derived = mnemonic_to_seed(mnemonic, VECTORS["passphrase"])
    assert derived.hex() == seed
    assert ExtendedKey.from_seed(derived).serialize() == xprv
    # BIP-39: 3 words per 32 bits of entropy (12, 15, 18, 21, or 24 words).
    assert len(mnemonic.split()) == len(entropy) * 4 * 3 // 32


def test_bip39_passphrase_changes_the_seed() -> None:
    _, mnemonic, seed, _ = VECTORS["english"][0]
    assert mnemonic_to_seed(mnemonic, "TREZOR").hex() == seed
    assert mnemonic_to_seed(mnemonic).hex() != seed
