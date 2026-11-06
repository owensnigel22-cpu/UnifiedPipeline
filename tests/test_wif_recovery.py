"""Partial-WIF stride search (own-key recovery with partial information).

Verified against an INDEPENDENT reference: a WIF built from a known key with
`keylab.encoding.wif.encode`, then blanked; recovery must return that exact
original key. The checksum/structure is validated by the separate `wif.decode`,
not by the search's own logic.
"""

from __future__ import annotations

import pytest

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, scalar_mult
from keylab.encoding import wif
from keylab.research.wif_recovery import recover_wif_from_template


def test_recovers_known_key_from_blanked_wif() -> None:
    key = 0x1234_5678_9ABC_DEF0_1111_2222_3333_4444_5555_6666_7777_8888_9999_AAAA_BBBB_CCCC
    original = wif.encode(key, compressed=True)
    # blank 3 interior characters
    template = original[:10] + "???" + original[13:]
    matches = recover_wif_from_template(template)
    hits = [m for m in matches if m["wif"] == original]
    assert hits, "the original WIF must be among the recovered candidates"
    assert hits[0]["private_key_hex"] == key.to_bytes(32, "big").hex()
    # every returned candidate is a genuinely checksum-valid WIF (independent decode)
    for m in matches:
        assert wif.decode(m["wif"])[0].hex() == m["private_key_hex"]


def test_public_key_filter_disambiguates() -> None:
    key = 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF
    original = wif.encode(key, compressed=True)
    pub = serialize_sec1(scalar_mult(key, G), compressed=True)
    template = original[:8] + "??" + original[10:]
    matches = recover_wif_from_template(template, expected_public_key=pub)
    assert len(matches) == 1
    assert matches[0]["wif"] == original
    assert matches[0]["private_key_hex"] == key.to_bytes(32, "big").hex()


def test_raises_on_oversized_search_space() -> None:
    # 5 wildcards => 58**5 ~= 656M candidates, far above the default bound.
    key = 0x42
    original = wif.encode(key, compressed=True)
    template = "?????" + original[5:]
    with pytest.raises(ValueError, match="exceeding max_candidates"):
        recover_wif_from_template(template)


def test_no_wildcards_returns_the_single_valid_key() -> None:
    original = wif.encode(0xC0FFEE, compressed=False)
    matches = recover_wif_from_template(original)
    assert len(matches) == 1 and matches[0]["wif"] == original


def test_rejects_bad_arguments() -> None:
    good = wif.encode(0x99, compressed=True)
    with pytest.raises(ValueError, match="template"):
        recover_wif_from_template("")
    with pytest.raises(ValueError, match="wildcard"):
        recover_wif_from_template(good, wildcard="??")
    with pytest.raises(ValueError, match="max_candidates"):
        recover_wif_from_template(good, max_candidates=0)
