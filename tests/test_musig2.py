"""BIP-327 MuSig2 KeyAgg/KeySort official vectors and legacy-mode regression."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keylab.advanced_suite import musig2_aggregate_keys
from keylab.ec.musig2 import (
    InvalidContributionError,
    KeyAggContext,
    apply_tweak,
    get_second_key,
    key_agg,
    key_agg_and_tweak,
    key_agg_coeff,
    key_sort,
)
from keylab.ec.secp256k1 import G, N, point_add_affine, scalar_mult

VECTOR_DIR = Path(__file__).parent / "vectors"
KEY_AGG = json.loads((VECTOR_DIR / "bip327_key_agg_vectors.json").read_text(encoding="utf-8"))
KEY_SORT = json.loads((VECTOR_DIR / "bip327_key_sort_vectors.json").read_text(encoding="utf-8"))
PUBKEYS = [bytes.fromhex(key) for key in KEY_AGG["pubkeys"]]
TWEAKS = [bytes.fromhex(tweak) for tweak in KEY_AGG["tweaks"]]


@pytest.mark.parametrize("case", KEY_AGG["valid_test_cases"], ids=lambda c: str(c["key_indices"]))
def test_bip327_key_agg_valid_vectors(case: dict[str, object]) -> None:
    keys = [PUBKEYS[i] for i in case["key_indices"]]  # type: ignore[union-attr]
    assert key_agg(keys).xonly.hex().upper() == case["expected"]


@pytest.mark.parametrize("case", KEY_AGG["error_test_cases"], ids=lambda c: c["comment"])
def test_bip327_key_agg_error_vectors(case: dict[str, object]) -> None:
    keys = [PUBKEYS[i] for i in case["key_indices"]]  # type: ignore[union-attr]
    tweaks = [TWEAKS[i] for i in case["tweak_indices"]]  # type: ignore[union-attr]
    error = case["error"]
    assert isinstance(error, dict)
    if error["type"] == "invalid_contribution":
        with pytest.raises(InvalidContributionError) as info:
            key_agg_and_tweak(keys, tweaks, case["is_xonly"])  # type: ignore[arg-type]
        assert info.value.signer == error["signer"]
        assert info.value.contrib == error["contrib"]
    else:
        with pytest.raises(ValueError, match=error["message"].replace(".", r"\.")):
            key_agg_and_tweak(keys, tweaks, case["is_xonly"])  # type: ignore[arg-type]


def test_bip327_key_sort_vector() -> None:
    keys = [bytes.fromhex(key) for key in KEY_SORT["pubkeys"]]
    assert [key.hex().upper() for key in key_sort(keys)] == KEY_SORT["sorted_pubkeys"]


def test_second_key_rule_gives_coefficient_one() -> None:
    keys = [PUBKEYS[0], PUBKEYS[0], PUBKEYS[1]]
    assert get_second_key(keys) == PUBKEYS[1]
    assert key_agg_coeff(keys, PUBKEYS[1]) == 1
    assert key_agg_coeff(keys, PUBKEYS[0]) != 1
    assert get_second_key([PUBKEYS[0]] * 3) == b"\x00" * 33


def test_apply_tweak_tracks_accumulators_for_plain_and_xonly_tweaks() -> None:
    base = key_agg(PUBKEYS[:3])
    tweak = (5).to_bytes(32, "big")
    plain = apply_tweak(base, tweak, False)
    assert plain.tacc == 5 and plain.gacc == 1
    assert plain.point == point_add_affine(base.point, scalar_mult(5, G))
    xonly = apply_tweak(base, tweak, True)
    expected_sign = N - 1 if base.point[1] % 2 else 1
    assert xonly.gacc == expected_sign
    # Q' = g*Q + t*G, where g negates Q first when an x-only tweak meets odd y.
    assert xonly.point == point_add_affine(scalar_mult(expected_sign, base.point), scalar_mult(5, G))
    assert isinstance(xonly, KeyAggContext) and len(xonly.plain) == 33


def test_advanced_suite_defaults_to_bip327_and_keeps_legacy_mode() -> None:
    keys = [key.hex() for key in PUBKEYS[:3]]
    bip327 = musig2_aggregate_keys(keys)
    assert bip327["mode"] == "bip327"
    assert bip327["x_only_aggregated_pubkey_hex"] == "0x" + KEY_AGG["valid_test_cases"][0]["expected"].lower()

    legacy = musig2_aggregate_keys(keys, mode="legacy-xonly")
    assert legacy["mode"] == "legacy-xonly"
    # Regression value from the pre-BIP-327 draft implementation.
    assert legacy["x_only_aggregated_pubkey_hex"] == (
        "0x075aa5bafddb850e1dbda433cedf1a71c39afc808fe1aa2ee4d71e809a4fee5d"
    )


def test_advanced_suite_bip327_mode_rejects_xonly_inputs() -> None:
    with pytest.raises(ValueError, match="legacy-xonly"):
        musig2_aggregate_keys([PUBKEYS[0][1:].hex(), PUBKEYS[1][1:].hex()])
    with pytest.raises(ValueError, match="mode"):
        musig2_aggregate_keys([PUBKEYS[0].hex(), PUBKEYS[1].hex()], mode="other")
