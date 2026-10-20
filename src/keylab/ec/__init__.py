"""Educational elliptic-curve arithmetic; not constant-time and not a production wallet backend."""

from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.ec.sec1 import parse_sec1, serialize_sec1
from keylab.ec.secp256k1 import (
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    point_add_affine,
    point_add_geometry,
    point_negate_affine,
    public_key_from_private_scalar,
    rfc6979_nonce_from_digest,
)

__all__ = [
    "ecdsa_sign_digest",
    "ecdsa_verify_digest",
    "parse_sec1",
    "point_add_affine",
    "point_add_geometry",
    "point_negate_affine",
    "public_key_from_private_scalar",
    "rfc6979_nonce_from_digest",
    "schnorr_public_key",
    "schnorr_sign",
    "schnorr_verify",
    "serialize_sec1",
]
