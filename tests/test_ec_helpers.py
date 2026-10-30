"""Shared ECC helpers and the modules consolidated onto them."""

from __future__ import annotations

import pytest

from keylab import advanced_suite
from keylab.ec import ecdsa_recovery, schnorr
from keylab.ec.secp256k1 import (
    G,
    N,
    P,
    has_even_y,
    lift_x,
    point_negate_affine,
    require_point,
    require_scalar,
    scalar_mult,
    sqrt_mod_p,
    y_from_x,
)
from keylab.encoding import taproot
from keylab.hashes.tagged import tagged_hash


def test_sqrt_mod_p_and_y_from_x_agree_with_the_curve_equation() -> None:
    assert sqrt_mod_p(4) in (2, P - 2)
    assert sqrt_mod_p(0) == 0
    x, y = G
    assert y_from_x(x, odd=bool(y & 1)) == y
    assert y_from_x(x, odd=not y & 1) == P - y
    with pytest.raises(ValueError):
        y_from_x(P)
    with pytest.raises(ValueError):
        y_from_x(5)  # 5^3 + 7 is not a square modulo P


def test_lift_x_returns_even_y_and_matches_every_consumer() -> None:
    point = scalar_mult(0xDEADBEEF, G)
    lifted = lift_x(point[0])
    assert has_even_y(lifted)
    assert lifted == (point if has_even_y(point) else point_negate_affine(point))
    # Every former private copy now routes through the shared helper.
    assert taproot.lift_x is lift_x
    assert schnorr._lift_x_even(point[0]) == lifted
    assert schnorr._lift_x_even(5) is None
    assert advanced_suite.lift_x_even(point[0]) == lifted
    assert advanced_suite.curve_y_roots(point[0]) == tuple(sorted({lifted[1], P - lifted[1]}))


def test_validation_helpers() -> None:
    assert require_point(G) == G
    for bad in (None, (1, 1), (0,)):
        with pytest.raises(ValueError):
            require_point(bad)  # type: ignore[arg-type]
    assert require_scalar(1) == 1
    for bad_scalar in (0, N, True, 1.5):
        with pytest.raises(ValueError):
            require_scalar(bad_scalar)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        has_even_y(None)


def test_advanced_suite_delegates_tagged_hash_and_curve_checks() -> None:
    assert advanced_suite.tagged_hash("TapTweak", b"abc") == tagged_hash("TapTweak", b"abc")
    assert advanced_suite.is_on_curve(G)
    assert not advanced_suite.is_on_curve((0, 0))


def test_ecdsa_recovery_still_recovers_after_sqrt_consolidation() -> None:
    from keylab.ec.secp256k1 import ecdsa_sign_digest

    digest = bytes(range(32))
    private = 0xC0FFEE
    signature = ecdsa_sign_digest(digest, private)
    assert scalar_mult(private, G) in ecdsa_recovery.recover_public_keys_from_signature(digest, signature)
