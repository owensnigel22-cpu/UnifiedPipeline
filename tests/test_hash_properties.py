from __future__ import annotations

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.hashes.reduced import ripemd160

try:
    hashlib.new("ripemd160")
except ValueError:
    pytestmark = pytest.mark.skip(reason="hashlib provider does not support RIPEMD-160")


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=0, max_size=128))
def test_ripemd160_matches_hashlib_for_bounded_messages(message: bytes) -> None:
    assert ripemd160(message) == hashlib.new("ripemd160", message).digest()
