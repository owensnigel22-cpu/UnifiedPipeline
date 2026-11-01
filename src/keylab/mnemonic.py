"""BIP-39 mnemonic generation, validation, and seed derivation (English wordlist).

Three separable stages: entropy generation (:func:`generate_entropy`), the
entropy <-> mnemonic conversion (:func:`entropy_to_mnemonic`,
:func:`mnemonic_to_entropy`), and seed derivation (:func:`mnemonic_to_seed`).
The official BIP-39 vectors are the oracle; where an assumption would conflict
with them, the vectors win.

Research/teaching code: not constant-time, not audited, no secure erasure of the
entropy, mnemonic, or seed in memory. Do not rely on a generated mnemonic for
funds -- use mature, audited wallet software for real assets. See SECURITY.md.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from importlib.resources import files

_WORD_COUNT = 2048
_WORD_BITS = 11  # 2**11 == 2048
VALID_ENTROPY_BITS: tuple[int, ...] = (128, 160, 192, 224, 256)
VALID_WORD_COUNTS: tuple[int, ...] = (12, 15, 18, 21, 24)


def _load_english_wordlist() -> tuple[str, ...]:
    """Load the packaged official BIP-39 English wordlist (2048 words)."""
    text = (files("keylab") / "data" / "bip39_english.txt").read_text(encoding="utf-8")
    words = tuple(text.split())
    if len(words) != _WORD_COUNT:
        raise RuntimeError(f"BIP-39 English wordlist must have {_WORD_COUNT} words, found {len(words)}")
    return words


ENGLISH_WORDLIST: tuple[str, ...] = _load_english_wordlist()
_WORD_INDEX: dict[str, int] = {word: index for index, word in enumerate(ENGLISH_WORDLIST)}


# --- entropy generation -------------------------------------------------------------------------

def generate_entropy(bits: int = 128) -> bytes:
    """Return cryptographically secure entropy of a BIP-39-valid size, from ``secrets``."""
    if bits not in VALID_ENTROPY_BITS:
        raise ValueError(f"entropy must be one of {VALID_ENTROPY_BITS} bits, not {bits}")
    return secrets.token_bytes(bits // 8)


# --- entropy <-> mnemonic conversion ------------------------------------------------------------

def _checksum_bits(entropy: bytes) -> tuple[int, int]:
    """Return (number of checksum bits, checksum value) for ``entropy`` per BIP-39."""
    cs_bits = len(entropy) * 8 // 32
    checksum = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> (256 - cs_bits)
    return cs_bits, checksum


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Encode entropy as a space-separated BIP-39 English mnemonic."""
    if not isinstance(entropy, (bytes, bytearray)):
        raise TypeError("entropy must be bytes")
    bits = len(entropy) * 8
    if bits not in VALID_ENTROPY_BITS:
        raise ValueError(f"entropy must be one of {VALID_ENTROPY_BITS} bits, not {bits}")
    cs_bits, checksum = _checksum_bits(bytes(entropy))
    combined = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    total_bits = bits + cs_bits
    words = [
        ENGLISH_WORDLIST[(combined >> (total_bits - _WORD_BITS * (position + 1))) & (_WORD_COUNT - 1)]
        for position in range(total_bits // _WORD_BITS)
    ]
    return " ".join(words)


def normalize_mnemonic(mnemonic: str) -> str:
    """NFKD-normalize and collapse whitespace to the canonical single-space form."""
    if not isinstance(mnemonic, str):
        raise TypeError("mnemonic must be a string")
    return " ".join(unicodedata.normalize("NFKD", mnemonic).split())


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Decode a BIP-39 mnemonic to its entropy, validating words and checksum.

    Raises ``ValueError`` for an unknown word, a wrong word count, or a checksum
    mismatch (an altered word). Leading/trailing and repeated whitespace are
    normalized; input is NFKD-normalized first.
    """
    words = normalize_mnemonic(mnemonic).split(" ") if normalize_mnemonic(mnemonic) else []
    if len(words) not in VALID_WORD_COUNTS:
        raise ValueError(f"mnemonic must have one of {VALID_WORD_COUNTS} words, not {len(words)}")
    unknown = [word for word in words if word not in _WORD_INDEX]
    if unknown:
        raise ValueError(f"mnemonic contains words not in the BIP-39 English list: {unknown[:4]}")

    combined = 0
    for word in words:
        combined = (combined << _WORD_BITS) | _WORD_INDEX[word]
    total_bits = len(words) * _WORD_BITS
    cs_bits = total_bits // 33  # total = ENT + CS, with CS = ENT / 32
    ent_bits = total_bits - cs_bits
    entropy = (combined >> cs_bits).to_bytes(ent_bits // 8, "big")
    expected_cs_bits, expected = _checksum_bits(entropy)
    if (combined & ((1 << cs_bits) - 1)) != expected or cs_bits != expected_cs_bits:
        raise ValueError("mnemonic checksum is invalid")
    return entropy


def is_valid_mnemonic(mnemonic: str) -> bool:
    """Return whether ``mnemonic`` is a well-formed BIP-39 mnemonic with a valid checksum."""
    try:
        mnemonic_to_entropy(mnemonic)
    except (ValueError, TypeError):
        return False
    return True


def generate_mnemonic(bits: int = 128) -> str:
    """Generate fresh entropy and return its BIP-39 mnemonic (not for real funds)."""
    return entropy_to_mnemonic(generate_entropy(bits))


# --- seed derivation ----------------------------------------------------------------------------

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive the 64-byte BIP-39 seed (NFKD, PBKDF2-HMAC-SHA512, 2048 iterations).

    The seed is defined for any passphrase and does not itself validate the
    mnemonic; call :func:`mnemonic_to_entropy` or :func:`is_valid_mnemonic` first
    when you need the checksum checked.
    """
    if not isinstance(mnemonic, str) or not isinstance(passphrase, str):
        raise TypeError("mnemonic and passphrase must be strings")
    phrase = unicodedata.normalize("NFKD", mnemonic)
    salt = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", phrase.encode(), salt.encode(), 2048, dklen=64)


__all__ = [
    "ENGLISH_WORDLIST",
    "VALID_ENTROPY_BITS",
    "VALID_WORD_COUNTS",
    "entropy_to_mnemonic",
    "generate_entropy",
    "generate_mnemonic",
    "is_valid_mnemonic",
    "mnemonic_to_entropy",
    "mnemonic_to_seed",
    "normalize_mnemonic",
]
