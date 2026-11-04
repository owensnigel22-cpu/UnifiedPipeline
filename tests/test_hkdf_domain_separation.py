"""HKDF domain-separation tests (RFC 5869).

Demonstrates that distinct context inputs derive independent key material from
the same IKM, that derivation is deterministic, and that salt and hash choice
change the output. These are additive; existing HKDF tests are untouched.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from keylab.crypto import hkdf

_IKM = b"master secret material for domain-separation tests"


def test_distinct_info_yields_distinct_output():
    for a, b in ((b"enc", b"mac"), (b"app/one", b"app/two"), (b"", b"x")):
        assert hkdf(_IKM, 32, info=a) != hkdf(_IKM, 32, info=b)


def test_same_inputs_are_deterministic():
    assert hkdf(_IKM, 32, salt=b"s", info=b"enc") == hkdf(_IKM, 32, salt=b"s", info=b"enc")


def test_distinct_salt_yields_distinct_output():
    assert hkdf(_IKM, 32, salt=b"salt-a", info=b"enc") != hkdf(_IKM, 32, salt=b"salt-b", info=b"enc")


def test_distinct_hash_name_yields_distinct_output():
    # amendment 3: same IKM + same info + same salt, different hash -> distinct output
    out256 = hkdf(_IKM, 32, salt=b"s", info=b"enc", hash_name="sha256")
    out512 = hkdf(_IKM, 32, salt=b"s", info=b"enc", hash_name="sha512")
    assert out256 != out512


@given(info_a=st.binary(max_size=16), info_b=st.binary(max_size=16))
def test_property_info_separation(info_a, info_b):
    out_a = hkdf(_IKM, 32, info=info_a)
    out_b = hkdf(_IKM, 32, info=info_b)
    # same label -> same key; different label -> different key
    assert (out_a == out_b) == (info_a == info_b)
