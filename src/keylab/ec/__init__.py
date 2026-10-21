"""Educational elliptic-curve arithmetic; not constant-time and not a production wallet backend."""

from keylab.ec.ecdsa_recovery import recover_public_keys_from_signature
from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.ec.sec1 import parse_sec1, serialize_sec1, serialize_uncompressed, serialize_xonly
from keylab.ec.secp256k1 import (
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    is_high_s_signature,
    point_add_affine,
    point_add_geometry,
    point_negate_affine,
    public_key_from_private_scalar,
    recover_private_key_from_reused_nonce,
    rfc6979_nonce_from_digest,
)

__all__ = [
    "ecdsa_sign_digest",
    "ecdsa_verify_digest",
    "is_high_s_signature",
    "parse_sec1",
    "point_add_affine",
    "point_add_geometry",
    "point_negate_affine",
    "public_key_from_private_scalar",
    "recover_private_key_from_reused_nonce",
    "recover_public_keys_from_signature",
    "rfc6979_nonce_from_digest",
    "schnorr_public_key",
    "schnorr_sign",
    "schnorr_verify",
    "serialize_sec1",
    "serialize_uncompressed",
    "serialize_xonly",
]
