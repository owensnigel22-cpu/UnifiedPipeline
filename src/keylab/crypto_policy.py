"""Centralized cryptographic algorithm allow-list for KeyLab.

A small, data-plus-pure-checks module stating which hash functions, signature
schemes, and RSA key sizes KeyLab considers acceptable *for study*. It is a
library primitive, **not** a runtime control: nothing in KeyLab's existing
public functions calls it, and it changes no behaviour. New code (or tests) may
validate inputs through the ``require_*`` / ``is_allowed_*`` helpers; existing
teaching crypto is unchanged.

Teaching/reference code: this documents what is acceptable for study, not a
certification of the implementations. See SECURITY.md. The allow-list deliberately
excludes legacy constructions (MD5, SHA-1, PKCS#1 v1.5 signatures) and, for new
signatures, RSA moduli below 2048 bits. There is intentionally no AEAD/symmetric
category yet: one will be added when a future milestone has an actual consumer.
"""

from __future__ import annotations

# --- allow-lists (stdlib types only; no third-party dependency) ---

#: Hash functions acceptable for new constructions (SHA-2 family).
ALLOWED_HASHES = frozenset({"sha256", "sha384", "sha512"})

#: Signature schemes acceptable for new signatures. ``rsa-pkcs1v15`` is excluded.
ALLOWED_SIGNATURE_SCHEMES = frozenset({"ecdsa-secp256k1", "schnorr-bip340", "rsa-pss-sha256"})

#: Minimum RSA modulus size in bits for new keys/signatures.
MIN_RSA_KEY_BITS = 2048


class PolicyError(ValueError):
    """Raised when an algorithm, scheme, or key size is outside the allow-list."""


def is_allowed_hash(name: str) -> bool:
    """Return whether ``name`` is an allow-listed hash function."""
    return name in ALLOWED_HASHES


def require_hash(name: str) -> str:
    """Return ``name`` if it is allow-listed, else raise :class:`PolicyError`."""
    if not is_allowed_hash(name):
        raise PolicyError(f"hash {name!r} is not allow-listed; use one of {sorted(ALLOWED_HASHES)}")
    return name


def is_allowed_signature_scheme(name: str) -> bool:
    """Return whether ``name`` is an allow-listed signature scheme."""
    return name in ALLOWED_SIGNATURE_SCHEMES


def require_signature_scheme(name: str) -> str:
    """Return ``name`` if it is allow-listed, else raise :class:`PolicyError`."""
    if not is_allowed_signature_scheme(name):
        raise PolicyError(
            f"signature scheme {name!r} is not allow-listed; "
            f"use one of {sorted(ALLOWED_SIGNATURE_SCHEMES)}"
        )
    return name


def is_allowed_rsa_key_bits(bits: int) -> bool:
    """Return whether ``bits`` meets the minimum RSA modulus size."""
    return type(bits) is int and bits >= MIN_RSA_KEY_BITS


def require_rsa_key_bits(bits: int) -> int:
    """Return ``bits`` if it meets the RSA minimum, else raise :class:`PolicyError`.

    This is an advisory check for *new* keys. It is intentionally **not** wired
    into :func:`keylab.crypto.generate_rsa_keypair`, which may generate small keys
    for teaching; a future opt-in ``strict`` path could use it.
    """
    if not is_allowed_rsa_key_bits(bits):
        raise PolicyError(f"RSA key size {bits!r} is below the {MIN_RSA_KEY_BITS}-bit minimum")
    return bits


__all__ = [
    "ALLOWED_HASHES",
    "ALLOWED_SIGNATURE_SCHEMES",
    "MIN_RSA_KEY_BITS",
    "PolicyError",
    "is_allowed_hash",
    "is_allowed_rsa_key_bits",
    "is_allowed_signature_scheme",
    "require_hash",
    "require_rsa_key_bits",
    "require_signature_scheme",
]
