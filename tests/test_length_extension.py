import hashlib
import json

import pytest

from keylab.cli import main
from keylab.hashes.length_extension import sha256_length_extend
from keylab.hashes.mac import hmac_sha256, verify_hmac_sha256


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
