"""Standard RSA encryption and signatures using maintained native crypto libraries."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RSAKeyMaterial:
    """An unencrypted PKCS#8 private PEM and matching SubjectPublicKeyInfo PEM."""

    private_key_pem: bytes
    public_key_pem: bytes


def _select_backend(backend: str) -> str:
    if backend not in {"auto", "cryptography", "pycryptodome"}:
        raise ValueError("backend must be auto, cryptography, or pycryptodome")
    if backend != "auto":
        return backend
    try:
        import cryptography  # noqa: F401
    except ImportError:
        try:
            import Crypto  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("install Keylab's crypto extra or crypto-alt extra") from exc
        return "pycryptodome"
    return "cryptography"


def generate_rsa_keypair(bits: int = 2048, *, backend: str = "auto") -> RSAKeyMaterial:
    """Generate RSA keys and serialize them as unencrypted PEM for local experiments."""
    if type(bits) is not int or bits < 2048 or bits % 256:
        raise ValueError("RSA key size must be an integer of at least 2048 and divisible by 256")
    selected = _select_backend(backend)
    if selected == "cryptography":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return RSAKeyMaterial(private_pem, public_pem)

    from Crypto.PublicKey import RSA

    private_key = RSA.generate(bits, e=65537)
    return RSAKeyMaterial(
        private_key.export_key(format="PEM", pkcs=8),
        private_key.public_key().export_key(format="PEM"),
    )


def rsa_oaep_encrypt(
    public_key_pem: bytes,
    message: bytes,
    *,
    label: bytes | None = None,
    backend: str = "auto",
) -> bytes:
    """Encrypt with RSA-OAEP using SHA-256 and MGF1-SHA-256."""
    selected = _select_backend(backend)
    if selected == "cryptography":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_public_key(public_key_pem)
        return key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )

    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA

    cipher = PKCS1_OAEP.new(RSA.import_key(public_key_pem), hashAlgo=SHA256, label=label or b"")
    return cipher.encrypt(message)


def rsa_oaep_decrypt(
    private_key_pem: bytes,
    ciphertext: bytes,
    *,
    label: bytes | None = None,
    backend: str = "auto",
) -> bytes:
    """Decrypt RSA-OAEP/SHA-256 ciphertext using the matching private PEM."""
    selected = _select_backend(backend)
    if selected == "cryptography":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_private_key(private_key_pem, password=None)
        return key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )

    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA

    cipher = PKCS1_OAEP.new(RSA.import_key(private_key_pem), hashAlgo=SHA256, label=label or b"")
    return cipher.decrypt(ciphertext)


def rsa_pss_sign(message: bytes, private_key_pem: bytes, *, backend: str = "auto") -> bytes:
    """Sign a message with RSA-PSS, SHA-256, MGF1-SHA-256, and a digest-length salt."""
    selected = _select_backend(backend)
    if selected == "cryptography":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(private_key_pem, password=None)
        return key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )

    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss

    digest = SHA256.new(message)
    return pss.new(RSA.import_key(private_key_pem), salt_bytes=SHA256.digest_size).sign(digest)


def rsa_pss_verify(
    message: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    backend: str = "auto",
) -> bool:
    """Verify RSA-PSS/SHA-256; malformed keys or signatures return False."""
    selected = _select_backend(backend)
    if selected == "cryptography":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        try:
            key = load_pem_public_key(public_key_pem)
            key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss

    try:
        pss.new(RSA.import_key(public_key_pem), salt_bytes=SHA256.digest_size).verify(
            SHA256.new(message), signature
        )
    except (ValueError, TypeError):
        return False
    return True


__all__ = [
    "RSAKeyMaterial",
    "generate_rsa_keypair",
    "rsa_oaep_decrypt",
    "rsa_oaep_encrypt",
    "rsa_pss_sign",
    "rsa_pss_verify",
]
