"""Forward public-key/address conversion and address target-hash decoding only."""

from __future__ import annotations

import hashlib

from keylab.ec.secp256k1 import (
    compress_pubkey,
    decompress_pubkey,
    is_on_curve,
    public_key_from_private_scalar,
)
from keylab.encoding import base58, bech32


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data)); requires a Python/OpenSSL RIPEMD-160 provider."""
    sha = hashlib.sha256(data).digest()
    try:
        ripemd = hashlib.new("ripemd160")
    except ValueError as exc:
        raise RuntimeError("this Python build does not provide RIPEMD-160") from exc
    ripemd.update(sha)
    return ripemd.digest()


def p2pkh_address(public_key: bytes, network: str = "mainnet") -> str:
    """Convert a serialized public key to a Base58Check P2PKH address."""
    versions = {"mainnet": 0x00, "testnet": 0x6F}
    try:
        version = versions[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    return base58.check_encode(bytes([version]) + hash160(public_key))


def p2wpkh_address(public_key: bytes, network: str = "mainnet") -> str:
    """Convert a serialized public key to a native SegWit P2WPKH address."""
    hrps = {"mainnet": "bc", "testnet": "tb"}
    try:
        hrp = hrps[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    return bech32.encode_segwit_address(hrp, 0, hash160(public_key))


def p2sh_p2wpkh_address(public_key: bytes, network: str = "mainnet") -> str:
    """Convert a serialized public key to a nested SegWit P2SH-P2WPKH address."""
    versions = {"mainnet": 0x05, "testnet": 0xC4}
    try:
        version = versions[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    redeem_script = b"\x00\x14" + hash160(public_key)
    return base58.check_encode(bytes([version]) + hash160(redeem_script))


def p2tr_address(internal_key_x: bytes, merkle_root: bytes = b"", network: str = "mainnet") -> str:
    """Build a P2TR address from an x-only internal key and optional Taproot root."""
    from keylab.encoding.taproot import taproot_output

    return taproot_output(internal_key_x, merkle_root, network=network).address


def address_to_target_hash(address: str) -> bytes:
    """Decode P2PKH, P2SH, P2WPKH, or P2TR payload data; never search for a preimage."""
    if "1" in address and address.lower().split("1", 1)[0] in ("bc", "tb", "bcrt"):
        hrp, version, program = bech32.decode_segwit_address(address)
        valid_program = (version == 0 and len(program) == 20) or (version == 1 and len(program) == 32)
        if hrp not in ("bc", "tb", "bcrt") or not valid_program:
            raise ValueError("only Bitcoin mainnet/testnet/regtest P2WPKH or P2TR programs are supported")
        return program
    payload = base58.check_decode(address)
    if len(payload) != 21 or payload[0] not in (0x00, 0x05, 0x6F, 0xC4):
        raise ValueError("only mainnet/testnet P2PKH or P2SH addresses are supported")
    return payload[1:]


def verify_pubkey_from_address(address: str, public_key: bytes) -> bool:
    """Verify a candidate secp256k1 public key against common Bitcoin address forms.

    This checks candidate->address consistency. It does not derive a public key
    from an address hash or recover a private key.
    """
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")
    if len(public_key) == 33:
        point = decompress_pubkey(public_key)
        compressed = public_key
    elif len(public_key) == 65 and public_key[0] == 4:
        point = (int.from_bytes(public_key[1:33], "big"), int.from_bytes(public_key[33:], "big"))
        if not is_on_curve(point):
            raise ValueError("uncompressed public key is not on secp256k1")
        compressed = compress_pubkey(point)
    else:
        raise ValueError("public key must be SEC compressed or uncompressed secp256k1 bytes")

    if "1" in address and address.lower().split("1", 1)[0] in ("bc", "tb", "bcrt"):
        hrp, version, program = bech32.decode_segwit_address(address)
        network = {"bc": "mainnet", "tb": "testnet", "bcrt": "regtest"}.get(hrp)
        if network is None:
            return False
        if version == 0 and len(program) == 20:
            return program == hash160(public_key)
        if version == 1 and len(program) == 32:
            from keylab.encoding.taproot import taproot_output_from_point

            output_key = taproot_output_from_point(point, network=network).output_key_x
            return program == output_key
        return False

    payload = base58.check_decode(address)
    if len(payload) != 21:
        return False
    version = payload[0]
    if version in (0x00, 0x6F):
        return payload[1:] == hash160(public_key)
    if version in (0x05, 0xC4):
        redeem_script = b"\x00\x14" + hash160(compressed)
        return payload[1:] == hash160(redeem_script)
    return False


def derive_addresses_from_wif(wif: str, *, reveal_private: bool = False) -> dict[str, object]:
    """Derive addresses from WIF; include private hex only when explicitly requested.

    Reuse HASH160(pubkey) across P2PKH, nested SegWit, and native SegWit
    encodings. ``bytes.hex()`` is retained for private-key hex because it is
    Python's C-implemented byte serializer; converting through an integer or
    formatting each byte in Python would add work.
    """
    from keylab.encoding.taproot import taproot_output_from_point
    from keylab.encoding.wif import decode

    key_bytes, compressed, network = decode(wif)
    point = public_key_from_private_scalar(int.from_bytes(key_bytes, "big"))
    public_key = compress_pubkey(point) if compressed else (
        b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    )
    key_hash = hash160(public_key)
    version = {"mainnet": 0x00, "testnet": 0x6F}[network]
    hrp = {"mainnet": "bc", "testnet": "tb"}[network]
    result: dict[str, object] = {
        "network": network,
        "compressed": compressed,
        "public_key_hex": public_key.hex(),
        "hash160_hex": key_hash.hex(),
        "p2pkh": base58.check_encode(bytes([version]) + key_hash),
        "p2sh_p2wpkh": (
            base58.check_encode(bytes([0x05 if network == "mainnet" else 0xC4])
                                + hash160(b"\x00\x14" + key_hash))
            if compressed else None
        ),
        "p2wpkh": bech32.encode_segwit_address(hrp, 0, key_hash) if compressed else None,
        "p2tr": taproot_output_from_point(point, network=network).address,
    }
    if reveal_private:
        result["private_key_hex"] = key_bytes.hex()
    return result


def address_belongs_to_wif(wif: str, target_address: str) -> dict[str, object]:
    """Check whether a supported address is one of the addresses derived from a WIF.

    The result identifies the matching address type and includes derived public
    addresses only; it never returns the WIF or private scalar. Bech32 addresses
    are compared case-insensitively after their checksum and format are validated.
    """
    address_to_target_hash(target_address)  # Validate format and checksum first.
    derived = derive_addresses_from_wif(wif)
    is_segwit = target_address.lower().startswith(("bc1", "tb1", "bcrt1"))
    target = target_address.lower() if is_segwit else target_address
    candidates = {
        name: address
        for name, address in derived.items()
        if name in {"p2pkh", "p2sh_p2wpkh", "p2wpkh", "p2tr"} and address is not None
    }
    matches = [
        name for name, address in candidates.items()
        if (str(address).lower() if is_segwit else address) == target
    ]
    return {
        "network": derived["network"],
        "compressed": derived["compressed"],
        "target_address": target_address,
        "derived_addresses": candidates,
        "matches": matches,
        "verified": bool(matches),
    }
