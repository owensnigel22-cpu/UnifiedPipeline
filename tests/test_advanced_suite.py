import hashlib

import pytest

from keylab.advanced_suite import batch_inv, rfc6979_deterministic_nonce
from keylab.ec.secp256k1 import rfc6979_nonce_from_digest


def test_batch_inv_handles_zero_and_normalizes_inputs_in_order() -> None:
    modulus = 101
    values = [2, 0, 5, -3, 101]
    inverses = batch_inv(values, modulus)

    assert inverses == [51, 0, 81, 67, 0]
    assert all((value * inverse) % modulus == 1 for value, inverse in zip(values, inverses) if value % modulus)
    assert batch_inv([], modulus) == []


@pytest.mark.parametrize("values,modulus", [([1, True], 101), ([1], 1)])
def test_batch_inv_rejects_bad_inputs(values: list[int], modulus: int) -> None:
    with pytest.raises(ValueError):
        batch_inv(values, modulus)


def test_advanced_suite_rfc6979_wrapper_matches_shared_digest_api() -> None:
    private_scalar = 7
    digest = hashlib.sha256(b"RFC6979 shared implementation").digest()
    nonce = rfc6979_nonce_from_digest(private_scalar, digest)

    assert rfc6979_deterministic_nonce(private_scalar, int.from_bytes(digest, "big")) == nonce
