"""ECDH shared-x derivation for secp256k1.

The pure-Python implementation is an independent, variable-time reference for
tests and education. ``backend="auto"`` prefers optional libsecp256k1 through
Coincurve and falls back to that reference when Coincurve is unavailable.
Neither the raw shared x-coordinate nor the Python fallback is a KDF; callers
must feed the returned bytes into an appropriate, context-bound KDF.
"""

from __future__ import annotations

from importlib.util import find_spec

from keylab.ec import reference
from keylab.ec.sec1 import parse_sec1, serialize_sec1
from keylab.ec.secp256k1 import Point, require_point, require_scalar

_BACKENDS = ("auto", "python", "coincurve")


def _validated_inputs(privkey: int, pubkey: Point | bytes) -> tuple[int, tuple[int, int]]:
    scalar = require_scalar(privkey, name="private scalar")
    if isinstance(pubkey, bytes):
        point = parse_sec1(pubkey)
    else:
        point = require_point(pubkey, name="public key")
    return scalar, point


def ecdh_reference(privkey: int, pubkey: Point | bytes) -> bytes:
    """Compute the secp256k1 ECDH shared x-coordinate using frozen Python math.

    ``privkey`` must be in ``[1, N-1]``. ``pubkey`` may be a finite affine
    point or a valid compressed/uncompressed SEC1 encoding. The result is the
    32-byte big-endian x-coordinate of ``privkey * pubkey``.

    This implementation is variable-time and must not protect production
    secrets.
    """
    scalar, point = _validated_inputs(privkey, pubkey)
    shared_point = reference.scalar_mult(scalar, point)
    if shared_point is None:
        raise ArithmeticError("ECDH multiplication produced the point at infinity")
    return shared_point[0].to_bytes(32, "big")


def ecdh_coincurve(privkey: int, pubkey: Point | bytes) -> bytes:
    """Compute the raw shared x-coordinate through libsecp256k1 via Coincurve.

    Coincurve's high-level ``PrivateKey.ecdh`` returns a hashed compressed
    point by default, so this adapter instead multiplies the validated public
    point by the private scalar and extracts x from compressed SEC1 encoding.
    """
    scalar, point = _validated_inputs(privkey, pubkey)
    try:
        from coincurve import PublicKey
    except (ImportError, OSError) as exc:
        raise ImportError("install KeyLab's optional Coincurve backend with `pip install 'keylab[fast]'`") from exc

    public = PublicKey(serialize_sec1(point, compressed=True))
    shared = public.multiply(scalar.to_bytes(32, "big"))
    encoded = shared.format(compressed=True)
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ArithmeticError("Coincurve returned an invalid compressed shared point")
    return encoded[1:]


def ecdh(
    privkey: int,
    pubkey: Point | bytes,
    *,
    backend: str = "auto",
) -> bytes:
    """Compute a raw secp256k1 shared x-coordinate.

    ``backend`` is ``"auto"`` (Coincurve if importable, otherwise Python),
    ``"coincurve"`` (require the native backend), or ``"python"`` (the
    variable-time reference). The default preserves optional-dependency
    behavior; callers handling real secrets should explicitly require a
    suitable native implementation.
    """
    if backend not in _BACKENDS:
        raise ValueError(f"backend must be one of: {', '.join(_BACKENDS)}")
    if backend == "python":
        return ecdh_reference(privkey, pubkey)
    if backend == "coincurve":
        return ecdh_coincurve(privkey, pubkey)
    if find_spec("coincurve") is None:
        return ecdh_reference(privkey, pubkey)
    try:
        return ecdh_coincurve(privkey, pubkey)
    except (ImportError, OSError):
        return ecdh_reference(privkey, pubkey)


__all__ = ["ecdh", "ecdh_coincurve", "ecdh_reference"]
