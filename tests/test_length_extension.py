import hashlib
import json

import pytest

from keylab.cli import main
from keylab.hashes import length_extension as le
from keylab.hashes.length_extension import (
    SUPPORTED_ALGORITHMS,
    length_extend,
    sha256_length_extend,
)
from keylab.hashes.mac import hmac_sha256, verify_hmac_sha256


@pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
@pytest.mark.parametrize("secret_length", [0, 5, 9, 55, 56, 64, 120])
def test_length_extend_matches_hashlib_oracle(algorithm: str, secret_length: int) -> None:
    secret = bytes((index * 37 + 11) & 0xFF for index in range(secret_length))
    known_message = b"amount=10&to=alice"
    append = b"&to=attacker"
    original = hashlib.new(algorithm, secret + known_message).digest()

    extension = length_extend(
        algorithm,
        original,
        secret_length + len(known_message),
        append,
        secret_len=secret_length,
    )
    forged_message = known_message + extension.glue_padding + append

    assert extension.algorithm == algorithm
    assert extension.appended == append
    assert forged_message.endswith(append)
    assert extension.forged_digest == hashlib.new(algorithm, secret + forged_message).digest()


def test_length_extension_constants_match_published_values() -> None:
    # Pin the from-first-principles derivations to the standard constants.
    assert le._SHA512_IV[0] == 0x6A09E667F3BCC908
    assert le._SHA512_K[0] == 0x428A2F98D728AE22
    assert le._SHA512_K[79] == 0x6C44198C4A475817
    assert le._MD5_K[0] == 0xD76AA478
    assert SUPPORTED_ALGORITHMS == ("md5", "sha1", "sha256", "sha512")


def test_length_extend_sha256_agrees_with_wrapper() -> None:
    secret, known_message, suffix = b"topsecret", b"user=bob", b"&role=admin"
    original = hashlib.sha256(secret + known_message).digest()

    generic = length_extend("sha256", original, len(secret) + len(known_message), suffix)
    wrapped = sha256_length_extend(original, known_message, len(secret), suffix)

    assert generic.glue_padding == wrapped.glue_padding
    assert generic.forged_digest == wrapped.forged_digest


def test_length_extend_rejects_invalid_arguments() -> None:
    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="algorithm must be one of"):
        length_extend("sha3", digest, 1, b"y")
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        length_extend("sha256", digest[:31], 1, b"y")
    with pytest.raises(ValueError, match="original_len must fit"):
        length_extend("sha256", digest, -1, b"y")
    with pytest.raises(ValueError, match="secret_len must be between"):
        length_extend("sha256", digest, 4, b"y", secret_len=5)
    with pytest.raises(TypeError, match="append must be bytes"):
        length_extend("sha256", digest, 4, "y")  # type: ignore[arg-type]


@pytest.mark.parametrize("original_length", [0, 1, 55, 56, 63, 64, 119, 120, 127, 128])
def test_length_extension_matches_hash_of_forged_naive_mac(
    original_length: int,
) -> None:
    secret = b"K" * 9
    known_message = b"M" * (original_length - len(secret)) if original_length >= len(secret) else b""
    secret = secret[:original_length]
    suffix = b"&admin=true"
    original_tag = hashlib.sha256(secret + known_message).digest()

    result = sha256_length_extend(original_tag, known_message, len(secret), suffix)

    assert result.forged_message == known_message + result.glue_padding + suffix
    assert result.forged_digest == hashlib.sha256(secret + result.forged_message).digest()


def test_hmac_tag_does_not_validate_length_extended_message() -> None:
    key, message, suffix = b"secret key", b"comment=hello", b"&admin=true"
    original_tag = hmac_sha256(key, message)
    extension = sha256_length_extend(original_tag, message, len(key), suffix)

    assert not verify_hmac_sha256(key, extension.forged_message, extension.forged_digest)
    assert not verify_hmac_sha256(key, extension.forged_message, original_tag)


@pytest.mark.parametrize(
    "digest,message,secret_length",
    [(bytes(31), b"m", 1), (bytes(32), b"m", -1)],
)
def test_length_extension_rejects_invalid_input(
    digest: bytes,
    message: bytes,
    secret_length: int,
) -> None:
    with pytest.raises(ValueError):
        sha256_length_extend(digest, message, secret_length, b"x")


def test_length_extension_cli_outputs_forgery(capsys) -> None:
    secret, message, suffix = b"key", b"data", b"&admin=true"
    tag = hashlib.sha256(secret + message).digest()

    assert main(
        [
            "sha256-length-extension",
            "--tag",
            tag.hex(),
            "--message",
            message.hex(),
            "--secret-length",
            str(len(secret)),
            "--suffix",
            suffix.hex(),
        ]
    ) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["forged_digest_hex"] == hashlib.sha256(
        secret + bytes.fromhex(output["forged_message_hex"])
    ).hexdigest()
    assert bytes.fromhex(output["forged_message_hex"]).endswith(suffix)
    assert "Educational demo only" in output["warning"]
