"""Tests for the crypto-policy allow-list.

The allow-list is a library primitive with zero production callers; these tests
assert (a) every algorithm KeyLab already uses is a member, and (b) legacy /
weak choices are rejected.
"""

from __future__ import annotations

import pytest

from keylab import crypto_policy as cp

# --- positive: what KeyLab already uses must be allow-listed ---

@pytest.mark.parametrize("name", ["sha256", "sha512"])  # HKDF uses these
def test_keylab_hashes_are_allowed(name):
    assert cp.is_allowed_hash(name)
    assert cp.require_hash(name) == name


@pytest.mark.parametrize("scheme", ["ecdsa-secp256k1", "schnorr-bip340", "rsa-pss-sha256"])
def test_keylab_signature_schemes_are_allowed(scheme):
    assert cp.is_allowed_signature_scheme(scheme)
    assert cp.require_signature_scheme(scheme) == scheme


def test_default_rsa_key_size_is_allowed():
    assert cp.is_allowed_rsa_key_bits(2048)       # generate_rsa_keypair default
    assert cp.require_rsa_key_bits(2048) == 2048
    assert cp.is_allowed_rsa_key_bits(4096)


# --- negative: legacy / weak choices must be rejected ---

@pytest.mark.parametrize("name", ["sha1", "md5", "sha224", "SHA256", "crc32"])
def test_disallowed_hashes_rejected(name):
    assert not cp.is_allowed_hash(name)
    with pytest.raises(cp.PolicyError):
        cp.require_hash(name)


@pytest.mark.parametrize("scheme", ["rsa-pkcs1v15", "dsa", "ed25519", "unknown"])
def test_disallowed_signature_schemes_rejected(scheme):
    assert not cp.is_allowed_signature_scheme(scheme)
    with pytest.raises(cp.PolicyError):
        cp.require_signature_scheme(scheme)


@pytest.mark.parametrize("bits", [512, 1024, 2047, 0, -1])
def test_small_rsa_rejected(bits):
    assert not cp.is_allowed_rsa_key_bits(bits)
    with pytest.raises(cp.PolicyError):
        cp.require_rsa_key_bits(bits)


def test_no_aead_category_present():
    # OQ3 -> (b): no placeholder AEAD allow-list until a consumer exists.
    assert not any(name.upper().find("AEAD") >= 0 for name in cp.__all__)
    assert not hasattr(cp, "ALLOWED_AEAD")


def test_policy_error_is_value_error():
    assert issubclass(cp.PolicyError, ValueError)
