"""Educational Merkle-Damgard length-extension for MD5, SHA-1, SHA-256, SHA-512.

Given ``H(secret || message)`` and the byte length of ``secret || message`` (but
NOT the secret), forge ``H(secret || message || glue || append)`` for an
attacker-chosen ``append``. This is a structural property of every plain
Merkle-Damgard hash (resume the finalized state and keep compressing); it needs
no search and recovers no secret. The lesson is "use HMAC, never
``H(secret || message)`` as a MAC".

The algorithm is the one implemented by iagox86/hash_extender; this pure-Python
port is cross-checked against the ``hashlib`` oracle for every supported hash and
many message lengths (the forged digest equals the real hash of the forged
message), which is the same correctness guarantee hash_extender provides. The
per-hash constants are derived from first principles (MD5 from ``sin``; SHA-512
from integer cube/square roots of the first primes) so no table is transcribed by
hand. Nothing here weakens any hash: it forges a digest for a controlled suffix
and does not invert the hash or recover the secret.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .reduced import _sha_compress

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF
_MAX_MESSAGE_BYTES = ((1 << 64) - 1) // 8


def _rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _rotr64(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & _MASK64


def _iroot(degree: int, value: int) -> int:
    """Return floor(value ** (1 / degree)) for nonnegative integers (exact)."""
    if value < 0:
        raise ValueError("value must be nonnegative")
    if value == 0:
        return 0
    high = 1
    while high**degree <= value:
        high <<= 1
    low = high >> 1
    while low < high:
        mid = (low + high + 1) >> 1
        if mid**degree <= value:
            low = mid
        else:
            high = mid - 1
    return low


def _first_primes(count: int) -> tuple[int, ...]:
    primes: list[int] = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % prime for prime in primes if prime * prime <= candidate):
            primes.append(candidate)
        candidate += 1
    return tuple(primes)


# --- MD5 -------------------------------------------------------------------

_MD5_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
_MD5_K = tuple(int(abs(math.sin(index + 1)) * (1 << 32)) & _MASK32 for index in range(64))
_MD5_S = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)


def _md5_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    words = [int.from_bytes(block[offset : offset + 4], "little") for offset in range(0, 64, 4)]
    a, b, c, d = state
    for index in range(64):
        if index < 16:
            mixed = (b & c) | (~b & d)
            schedule = index
        elif index < 32:
            mixed = (d & b) | (~d & c)
            schedule = (5 * index + 1) % 16
        elif index < 48:
            mixed = b ^ c ^ d
            schedule = (3 * index + 5) % 16
        else:
            mixed = c ^ (b | (~d & _MASK32))
            schedule = (7 * index) % 16
        mixed = (mixed + a + _MD5_K[index] + words[schedule]) & _MASK32
        a, d, c = d, c, b
        b = (b + _rotl32(mixed, _MD5_S[index])) & _MASK32
    return tuple((old + new) & _MASK32 for old, new in zip(state, (a, b, c, d)))


# --- SHA-1 -----------------------------------------------------------------

_SHA1_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def _sha1_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    words = [int.from_bytes(block[offset : offset + 4], "big") for offset in range(0, 64, 4)]
    for index in range(16, 80):
        words.append(_rotl32(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], 1))
    a, b, c, d, e = state
    for index in range(80):
        if index < 20:
            mixed = (b & c) | (~b & d)
            constant = 0x5A827999
        elif index < 40:
            mixed = b ^ c ^ d
            constant = 0x6ED9EBA1
        elif index < 60:
            mixed = (b & c) | (b & d) | (c & d)
            constant = 0x8F1BBCDC
        else:
            mixed = b ^ c ^ d
            constant = 0xCA62C1D6
        temp = (_rotl32(a, 5) + mixed + e + constant + words[index]) & _MASK32
        e, d, c, b, a = d, c, _rotl32(b, 30), a, temp
    return tuple((old + new) & _MASK32 for old, new in zip(state, (a, b, c, d, e)))


# --- SHA-512 ---------------------------------------------------------------

_PRIMES_80 = _first_primes(80)
_SHA512_IV = tuple(_iroot(2, prime << 128) & _MASK64 for prime in _PRIMES_80[:8])
_SHA512_K = tuple(_iroot(3, prime << 192) & _MASK64 for prime in _PRIMES_80)


def _sha512_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    words = [int.from_bytes(block[offset : offset + 8], "big") for offset in range(0, 128, 8)]
    for index in range(16, 80):
        x, y = words[index - 15], words[index - 2]
        sigma0 = _rotr64(x, 1) ^ _rotr64(x, 8) ^ (x >> 7)
        sigma1 = _rotr64(y, 19) ^ _rotr64(y, 61) ^ (y >> 6)
        words.append((words[index - 16] + sigma0 + words[index - 7] + sigma1) & _MASK64)
    a, b, c, d, e, f, g, h = state
    for index in range(80):
        upper_sigma1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        choice = (e & f) ^ (~e & g)
        temp1 = (h + upper_sigma1 + choice + _SHA512_K[index] + words[index]) & _MASK64
        upper_sigma0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (upper_sigma0 + majority) & _MASK64
        a, b, c, d, e, f, g, h = (temp1 + temp2) & _MASK64, a, b, c, (d + temp1) & _MASK64, e, f, g
    return tuple((old + new) & _MASK64 for old, new in zip(state, (a, b, c, d, e, f, g, h)))


def _sha256_from_state(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    return _sha_compress(block, state, 64)


# --- generic Merkle-Damgard driver ----------------------------------------


@dataclass(frozen=True)
class _MerkleDamgard:
    name: str
    digest_size: int
    block_size: int
    length_field_size: int
    word_size: int
    byteorder: Literal["big", "little"]
    compress: Callable[[tuple[int, ...], bytes], tuple[int, ...]]

    def parse_state(self, digest: bytes) -> tuple[int, ...]:
        return tuple(
            int.from_bytes(digest[offset : offset + self.word_size], self.byteorder)
            for offset in range(0, self.digest_size, self.word_size)
        )

    def serialize_state(self, state: tuple[int, ...]) -> bytes:
        return b"".join(word.to_bytes(self.word_size, self.byteorder) for word in state)

    def padding(self, message_length: int) -> bytes:
        target = (self.block_size - self.length_field_size) % self.block_size
        pad = b"\x80"
        pad += b"\0" * ((target - (message_length + 1)) % self.block_size)
        length_order: Literal["big", "little"] = "little" if self.name == "md5" else "big"
        return pad + (message_length * 8).to_bytes(self.length_field_size, length_order)


_ALGORITHMS: dict[str, _MerkleDamgard] = {
    "md5": _MerkleDamgard("md5", 16, 64, 8, 4, "little", _md5_compress),
    "sha1": _MerkleDamgard("sha1", 20, 64, 8, 4, "big", _sha1_compress),
    "sha256": _MerkleDamgard("sha256", 32, 64, 8, 4, "big", _sha256_from_state),
    "sha512": _MerkleDamgard("sha512", 64, 128, 16, 8, "big", _sha512_compress),
}

SUPPORTED_ALGORITHMS: tuple[str, ...] = tuple(_ALGORITHMS)


@dataclass(frozen=True)
class LengthExtension:
    """Forged digest and the glue padding for a Merkle-Damgard length extension."""

    algorithm: str
    glue_padding: bytes
    forged_digest: bytes
    appended: bytes


def length_extend(
    algorithm: str,
    original_digest: bytes,
    original_len: int,
    append: bytes,
    *,
    secret_len: int | None = None,
) -> LengthExtension:
    """Forge ``H(original || glue || append)`` from ``H(original)`` and ``len(original)``.

    ``algorithm`` is one of :data:`SUPPORTED_ALGORITHMS`. ``original_digest`` is
    ``H(secret || known_message)``; ``original_len`` is the byte length of that
    hashed ``secret || known_message`` (as a real attacker would guess it); and
    ``append`` is the attacker-chosen suffix. The returned ``glue_padding`` is the
    Merkle-Damgard padding for the original message, so the forged message tail to
    append to the known data is ``glue_padding + append`` and the full forged
    message hashes (under the secret) to ``forged_digest`` -- all without the
    secret. ``secret_len``, if given, must lie in ``[0, original_len]`` and is
    recorded for context only; it does not affect the arithmetic.
    """
    spec = _ALGORITHMS.get(algorithm)
    if spec is None:
        raise ValueError(f"algorithm must be one of {', '.join(SUPPORTED_ALGORITHMS)}")
    if len(original_digest) != spec.digest_size:
        raise ValueError(f"{algorithm} digest must be exactly {spec.digest_size} bytes")
    if not isinstance(original_len, int) or not 0 <= original_len <= _MAX_MESSAGE_BYTES:
        raise ValueError("original_len must fit the hash 64-bit bit-length field")
    if secret_len is not None and not 0 <= secret_len <= original_len:
        raise ValueError("secret_len must be between 0 and original_len")
    if not isinstance(append, (bytes, bytearray)):
        raise TypeError("append must be bytes")

    append = bytes(append)
    glue_padding = spec.padding(original_len)
    processed_length = original_len + len(glue_padding)
    extended_length = processed_length + len(append)
    continuation = append + spec.padding(extended_length)

    state = spec.parse_state(original_digest)
    for offset in range(0, len(continuation), spec.block_size):
        state = spec.compress(state, continuation[offset : offset + spec.block_size])
    return LengthExtension(algorithm, glue_padding, spec.serialize_state(state), append)


# --- backward-compatible SHA-256 wrappers ----------------------------------


@dataclass(frozen=True)
class SHA256LengthExtension:
    """Forged suffix, glue padding, full message, and resulting SHA-256 digest."""

    glue_padding: bytes
    forged_message: bytes
    forged_digest: bytes


def _sha256_padding(message_length: int) -> bytes:
    if not 0 <= message_length <= _MAX_MESSAGE_BYTES:
        raise ValueError("message length must fit the SHA-256 64-bit bit-length field")
    return _ALGORITHMS["sha256"].padding(message_length)


def sha256_length_extend(
    original_digest: bytes,
    known_message: bytes,
    secret_length: int,
    suffix: bytes,
) -> SHA256LengthExtension:
    """Extend ``SHA256(secret || known_message)`` without knowing the secret.

    The caller supplies the guessed secret length, as a real attack would.
    This helper is for demonstrating the weakness of secret-prefix SHA-256 MACs;
    use HMAC-SHA-256 for authentication instead. It is a thin wrapper over
    :func:`length_extend` for ``"sha256"``.
    """
    if len(original_digest) != 32:
        raise ValueError("original_digest must be exactly 32 bytes")
    if secret_length < 0:
        raise ValueError("secret_length must be nonnegative")

    original_length = secret_length + len(known_message)
    extension = length_extend(
        "sha256", original_digest, original_length, bytes(suffix), secret_len=secret_length
    )
    forged_message = bytes(known_message) + extension.glue_padding + bytes(suffix)
    return SHA256LengthExtension(extension.glue_padding, forged_message, extension.forged_digest)


__all__ = [
    "SUPPORTED_ALGORITHMS",
    "LengthExtension",
    "SHA256LengthExtension",
    "length_extend",
    "sha256_length_extend",
]
