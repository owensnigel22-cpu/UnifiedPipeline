"""Educational elliptic-curve arithmetic; not constant-time and not a production wallet backend."""

from keylab.ec.secp256k1 import (
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    point_add_affine,
    point_add_geometry,
    point_negate_affine,
    public_key_from_private_scalar,
)

__all__ = [
    "ecdsa_sign_digest",
    "ecdsa_verify_digest",
    "point_add_affine",
    "point_add_geometry",
    "point_negate_affine",
    "public_key_from_private_scalar",
]
