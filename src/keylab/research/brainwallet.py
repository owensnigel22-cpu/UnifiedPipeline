"""Brainwallet dictionary attack — an educational demonstration of weak key choice.

A *brainwallet* derives a Bitcoin private key straight from a human-chosen
passphrase: ``d = SHA256(passphrase)``. Because people pick guessable phrases, the
key space collapses from 2**256 to the size of a wordlist, so brainwallets are
trivially broken. This module shows that weakness on a **single caller-supplied
target address** and a local wordlist. It is deliberately **offline**: it never
queries balances, never touches the network, and never scans the chain for funded
keys — it only answers "does any passphrase in this list derive this one address?"
so the lesson (don't use brainwallets) can be taught and tested reproducibly.

See ``SECURITY.md`` and ``docs/references.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N, Point, scalar_mult
from keylab.encoding.address import address_to_target_hash, hash160
from keylab.research.forensics.bloom import BloomFilter


def passphrase_to_privkey(passphrase: bytes) -> int:
    """Return the brainwallet private key ``int(SHA256(passphrase))``.

    Raises :class:`ValueError` if the digest is 0 or >= the group order ``N`` (both
    astronomically unlikely, but not valid secp256k1 scalars).
    """
    if not isinstance(passphrase, (bytes, bytearray)):
        raise TypeError("passphrase must be bytes")
    scalar = int.from_bytes(sha256(passphrase).digest(), "big")
    if not 1 <= scalar < N:
        raise ValueError("passphrase hashes outside the valid scalar range")
    return scalar


def passphrase_to_pubkeys(passphrase: bytes) -> dict[str, bytes]:
    """Return the compressed and uncompressed SEC public keys for a passphrase."""
    point: Point = scalar_mult(passphrase_to_privkey(passphrase), G)
    return {
        "compressed": serialize_sec1(point, compressed=True),
        "uncompressed": serialize_sec1(point, compressed=False),
    }


def passphrase_hash160s(passphrase: bytes) -> dict[str, bytes]:
    """Return the HASH160 of each SEC form (the P2PKH / P2WPKH witness program)."""
    return {form: hash160(sec) for form, sec in passphrase_to_pubkeys(passphrase).items()}


def iter_wordlist(path: str | Path) -> Iterator[bytes]:
    """Stream a wordlist line by line in **binary** mode (no full-file buffering).

    Each yielded candidate has its trailing CR/LF stripped; blank lines are skipped.
    Binary mode avoids decode errors on real-world lists (e.g. ``rockyou.txt``).
    """
    with Path(path).open("rb") as handle:
        for raw in handle:
            candidate = raw.rstrip(b"\r\n")
            if candidate:
                yield candidate


@dataclass(frozen=True)
class BrainwalletResult:
    """Outcome of a brainwallet dictionary attack against one target address."""

    found: bool
    passphrase: bytes | None
    private_key_hex: str | None
    tried: int
    target_hash160: str
    matched_form: str | None  # "compressed" or "uncompressed"


def crack_brainwallet(
    target_address: str,
    wordlist_path: str | Path,
    *,
    reveal_private_key: bool = False,
    limit: int | None = None,
    progress: Callable[[int], None] | None = None,
) -> BrainwalletResult:
    """Search ``wordlist_path`` for a passphrase whose key yields ``target_address``.

    Matching is done on HASH160, so it covers both P2PKH and P2WPKH(v0) for either
    the compressed or uncompressed public key. The private key is only included in
    the result when ``reveal_private_key`` is set. ``limit`` caps the number of
    candidates tried; ``progress`` (if given) is called with the running count every
    10,000 candidates. Entirely offline — no balance or network lookups.
    """
    target_hash = address_to_target_hash(target_address)
    if len(target_hash) != 20:
        raise ValueError("target address must be a HASH160 address (P2PKH or P2WPKH v0)")
    tried = 0
    for passphrase in iter_wordlist(wordlist_path):
        if limit is not None and tried >= limit:
            break
        tried += 1
        if progress is not None and tried % 10_000 == 0:
            progress(tried)
        try:
            hashes = passphrase_hash160s(passphrase)
        except ValueError:  # pragma: no cover - vanishingly rare out-of-range digest
            continue
        for form, candidate_hash in hashes.items():
            if candidate_hash == target_hash:
                private_hex = None
                if reveal_private_key:
                    private_hex = f"{passphrase_to_privkey(passphrase):064x}"
                return BrainwalletResult(
                    found=True,
                    passphrase=passphrase,
                    private_key_hex=private_hex,
                    tried=tried,
                    target_hash160=target_hash.hex(),
                    matched_form=form,
                )
    return BrainwalletResult(
        found=False,
        passphrase=None,
        private_key_hex=None,
        tried=tried,
        target_hash160=target_hash.hex(),
        matched_form=None,
    )


@dataclass(frozen=True)
class BrainwalletHit:
    """One passphrase whose derived HASH160 matched a target in a multi-target scan."""

    passphrase: bytes
    target_hash160: bytes
    matched_form: str  # "compressed" or "uncompressed"
    private_key_hex: str | None


def _derive_hash160s(passphrase: bytes) -> dict[str, bytes] | None:
    try:
        return passphrase_hash160s(passphrase)
    except ValueError:  # pragma: no cover - vanishingly rare out-of-range digest
        return None


def _scan_chunk(
    passphrases: Sequence[bytes],
    bloom: BloomFilter,
    targets: frozenset[bytes],
    reveal_private_key: bool,
) -> list[BrainwalletHit]:
    hits: list[BrainwalletHit] = []
    for passphrase in passphrases:
        hashes = _derive_hash160s(passphrase)
        if hashes is None:
            continue
        for form, candidate_hash in hashes.items():
            # Bloom pre-screen (no false negatives), then the exact set confirms.
            if candidate_hash in bloom and candidate_hash in targets:
                private_hex = (
                    f"{passphrase_to_privkey(passphrase):064x}" if reveal_private_key else None
                )
                hits.append(BrainwalletHit(passphrase, candidate_hash, form, private_hex))
    return hits


_WORKER_STATE: dict[str, object] = {}


def _init_worker(bloom: BloomFilter, targets: frozenset[bytes], reveal: bool) -> None:
    _WORKER_STATE["bloom"] = bloom
    _WORKER_STATE["targets"] = targets
    _WORKER_STATE["reveal"] = reveal


def _process_scan(chunk: Sequence[bytes]) -> list[BrainwalletHit]:
    return _scan_chunk(
        chunk,
        cast(BloomFilter, _WORKER_STATE["bloom"]),
        cast("frozenset[bytes]", _WORKER_STATE["targets"]),
        bool(_WORKER_STATE["reveal"]),
    )


def _chunked(items: Iterable[bytes], size: int) -> Iterator[list[bytes]]:
    chunk: list[bytes] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def crack_brainwallet_multi(
    passphrases: Iterable[bytes],
    targets: Iterable[bytes],
    *,
    reveal_private_key: bool = False,
    executor: str = "thread",
    workers: int | None = None,
    chunk_size: int = 1024,
) -> list[BrainwalletHit]:
    """Search ``passphrases`` for any that derive a HASH160 in ``targets``.

    A Bloom filter pre-screens each derived HASH160 before the exact set check, which
    keeps many-target scans fast. ``executor`` selects ``"serial"``, ``"thread"``, or
    ``"process"`` parallelism; derivation is CPU-bound pure-Python EC math, so measure
    before assuming threads help (the GIL limits them). Returns every hit found; the
    private key appears only when ``reveal_private_key`` is set. Offline -- no network.
    """
    if executor not in ("serial", "thread", "process"):
        raise ValueError("executor must be 'serial', 'thread', or 'process'")
    if type(chunk_size) is not int or chunk_size < 1:
        raise ValueError("chunk_size must be a positive integer")
    target_set = frozenset(bytes(target) for target in targets)
    for target in target_set:
        if len(target) != 20:
            raise ValueError("each target must be a 20-byte HASH160")
    if not target_set:
        return []
    bloom = BloomFilter.from_items(target_set)

    chunks = _chunked(passphrases, chunk_size)
    hits: list[BrainwalletHit] = []
    if executor == "serial":
        for chunk in chunks:
            hits.extend(_scan_chunk(chunk, bloom, target_set, reveal_private_key))
        return hits
    if executor == "thread":
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for chunk_hits in pool.map(
                lambda chunk: _scan_chunk(chunk, bloom, target_set, reveal_private_key),
                chunks,
            ):
                hits.extend(chunk_hits)
        return hits
    with ProcessPoolExecutor(
        max_workers=workers,
        initializer=_init_worker,
        initargs=(bloom, target_set, reveal_private_key),
    ) as pool:
        for chunk_hits in pool.map(_process_scan, chunks):
            hits.extend(chunk_hits)
    return hits


__all__ = [
    "BrainwalletHit",
    "BrainwalletResult",
    "crack_brainwallet",
    "crack_brainwallet_multi",
    "iter_wordlist",
    "passphrase_hash160s",
    "passphrase_to_privkey",
    "passphrase_to_pubkeys",
]
