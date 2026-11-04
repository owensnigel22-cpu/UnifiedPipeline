"""Tests for the constant-time comparison leaf helper."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from keylab._ct import constant_time_equal


def test_equal_returns_true():
    assert constant_time_equal(b"\x00\x01\x02", b"\x00\x01\x02") is True


def test_equal_length_differing_returns_false():
    assert constant_time_equal(b"\x00\x01\x02", b"\x00\x01\x03") is False


def test_different_length_returns_false_without_raising():
    # length mismatch must be a False result, not an exception or short-circuit
    assert constant_time_equal(b"abc", b"abcd") is False
    assert constant_time_equal(b"", b"\x00") is False
    assert constant_time_equal(b"", b"") is True


def test_bytearray_accepted():
    assert constant_time_equal(bytearray(b"abc"), b"abc") is True
    assert constant_time_equal(bytearray(b"abc"), bytearray(b"abd")) is False


@pytest.mark.parametrize("bad", ["abc", 123, None, ["a"], ("a",)])
def test_non_bytes_rejected(bad):
    with pytest.raises(TypeError):
        constant_time_equal(bad, b"abc")
    with pytest.raises(TypeError):
        constant_time_equal(b"abc", bad)


@given(a=st.binary(), b=st.binary())
def test_property_matches_equality_operator(a, b):
    assert constant_time_equal(a, b) == (a == b)
