"""Bech32/Bech32m and SegWit address encoding; this does not invert address hashes."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_REV = {character: index for index, character in enumerate(CHARSET)}
BECH32 = "bech32"
BECH32M = "bech32m"
_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _create_checksum(hrp: str, data: list[int], spec: str) -> list[int]:
    constant = 1 if spec == BECH32 else 0x2BC830A3
    polymod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ constant
    return [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]


def encode(hrp: str, data: list[int], spec: str = BECH32) -> str:
    """Encode 5-bit data using the selected checksum variant."""
    if not hrp or any(ord(char) < 33 or ord(char) > 126 for char in hrp):
        raise ValueError("HRP must contain printable ASCII characters")
    if hrp.lower() != hrp:
        raise ValueError("HRP must be lowercase")
    if spec not in (BECH32, BECH32M):
        raise ValueError("checksum spec must be 'bech32' or 'bech32m'")
    if any(value < 0 or value > 31 for value in data):
        raise ValueError("data values must fit in 5 bits")
    combined = data + _create_checksum(hrp, data, spec)
    result = hrp + "1" + "".join(CHARSET[value] for value in combined)
    if len(result) > 90:
        raise ValueError("Bech32 string exceeds 90 characters")
    return result


def decode(text: str) -> tuple[str, list[int], str]:
    """Decode a Bech32 string and return its HRP, data without checksum, and checksum spec."""
    if not 8 <= len(text) <= 90:
        raise ValueError("Bech32 string length must be between 8 and 90 characters")
    if text.lower() != text and text.upper() != text:
        raise ValueError("mixed-case Bech32 strings are invalid")
    text = text.lower()
    separator = text.rfind("1")
    if separator < 1 or separator + 7 > len(text):
        raise ValueError("invalid Bech32 separator or data length")
    hrp = text[:separator]
    if any(ord(char) < 33 or ord(char) > 126 for char in text):
        raise ValueError("Bech32 contains non-printable characters")
    try:
        values = [_CHARSET_REV[char] for char in text[separator + 1 :]]
    except KeyError as exc:
        raise ValueError(f"invalid Bech32 character: {exc.args[0]!r}") from exc
    polymod = _polymod(_hrp_expand(hrp) + values)
    if polymod == 1:
        spec = BECH32
    elif polymod == 0x2BC830A3:
        spec = BECH32M
    else:
        raise ValueError("Bech32 checksum mismatch")
    return hrp, values[:-6], spec


def convertbits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool) -> list[int]:
    """Convert a sequence between bit widths, rejecting invalid or non-zero padding."""
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("input value does not fit source bit width")
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & max_value)
    if pad:
        if bit_count:
            result.append((accumulator << (to_bits - bit_count)) & max_value)
    elif bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & max_value):
        raise ValueError("invalid or non-zero bit conversion padding")
    return result


def encode_segwit_address(hrp: str, version: int, program: bytes) -> str:
    """Encode a SegWit witness program, selecting Bech32m for witness v1 and later."""
    if not 0 <= version <= 16:
        raise ValueError("witness version must be between 0 and 16")
    if not 2 <= len(program) <= 40 or (version == 0 and len(program) not in (20, 32)):
        raise ValueError("invalid witness program length")
    spec = BECH32 if version == 0 else BECH32M
    return encode(hrp, [version] + convertbits(program, 8, 5, True), spec)


def decode_segwit_address(text: str) -> tuple[str, int, bytes]:
    """Decode and validate a SegWit address, including version-specific checksum rules."""
    hrp, data, spec = decode(text)
    if not data or data[0] > 16:
        raise ValueError("invalid witness version")
    version = data[0]
    if (version == 0 and spec != BECH32) or (version != 0 and spec != BECH32M):
        raise ValueError("wrong checksum variant for witness version")
    program = bytes(convertbits(data[1:], 5, 8, False))
    if not 2 <= len(program) <= 40 or (version == 0 and len(program) not in (20, 32)):
        raise ValueError("invalid witness program length")
    return hrp, version, program

__all__ = [
    "BECH32",
    "BECH32M",
    "CHARSET",
    "convertbits",
    "decode",
    "decode_segwit_address",
    "encode",
    "encode_segwit_address",
]
