"""Partial-WIF stride search: recover an own key from a WIF with wildcard characters.

Mathematical role: given a Wallet Import Format string with some characters
unknown (wildcards), enumerate the reduced keyspace of ``58**(#wildcards)``
candidates and keep only those whose Base58Check checksum validates (checksum
pruning cuts ~all but ~2**-32 of candidates), optionally confirming against a
known public key.

Scope boundary: this recovers *your own* partially-known key from a template you
supply -- the same category as KeyLab's existing WIF tooling. It is **not**
general address-to-private-key derivation: it never searches for a key given
only a public key/address, and it **raises** if the wildcard pattern implies a
search larger than an explicit, documented bound rather than attempting it.

Idea source: the missing-character / stride WIF search in PawelGorny's Kangaroo
fork and WifSolverCuda (GPLv3) -- idea only, re-implemented. See CREDITS.md. For
a *contiguous* unknown scalar range with a known public key, the bounded-interval
solvers :func:`keylab.research.ecdlp.bsgs.baby_step_giant_step` /
``pollard_kangaroo`` are the right tool instead (character wildcards do not form
a contiguous scalar interval, so they are enumerated here).
"""

from __future__ import annotations

from itertools import product

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, scalar_mult
from keylab.encoding import wif
from keylab.encoding.base58 import ALPHABET

__all__ = ["DEFAULT_MAX_CANDIDATES", "recover_wif_from_template"]

DEFAULT_MAX_CANDIDATES = 500_000  # explicit, documented bound; raise above it


def recover_wif_from_template(
    template: str,
    *,
    wildcard: str = "?",
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    expected_public_key: bytes | None = None,
) -> list[dict[str, object]]:
    """Return every checksum-valid key matching a WIF ``template`` with ``wildcard`` chars.

    Raises ``ValueError`` if ``58**(#wildcards)`` exceeds ``max_candidates`` (never
    attempts an unbounded or oversized search silently). With
    ``expected_public_key`` (SEC1 bytes) only candidates whose public key matches
    are returned -- the legitimate "confirm my own key" path.
    """
    if not isinstance(template, str) or not template:
        raise ValueError("template must be a non-empty WIF string")
    if not isinstance(wildcard, str) or len(wildcard) != 1:
        raise ValueError("wildcard must be a single character")
    if type(max_candidates) is not int or max_candidates < 1:
        raise ValueError("max_candidates must be a positive integer")

    positions = [i for i, ch in enumerate(template) if ch == wildcard]
    search_space = len(ALPHABET) ** len(positions)
    if search_space > max_candidates:
        raise ValueError(
            f"wildcard pattern implies {search_space} candidates "
            f"(58**{len(positions)}), exceeding max_candidates={max_candidates}; "
            "refusing to attempt an oversized search -- narrow the template or raise the bound"
        )

    results: list[dict[str, object]] = []
    chars = list(template)
    for combo in product(ALPHABET, repeat=len(positions)):
        for pos, ch in zip(positions, combo):
            chars[pos] = ch
        candidate = "".join(chars)
        try:
            key_bytes, compressed, network = wif.decode(candidate)  # Base58Check prune
        except ValueError:
            continue
        if expected_public_key is not None:
            point = scalar_mult(int.from_bytes(key_bytes, "big"), G)
            if serialize_sec1(point, compressed=compressed) != expected_public_key:
                continue
        results.append(
            {
                "wif": candidate,
                "private_key_hex": key_bytes.hex(),
                "compressed": compressed,
                "network": network,
            }
        )
    return results
