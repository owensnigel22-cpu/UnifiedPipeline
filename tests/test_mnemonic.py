"""BIP-39 mnemonic generation and recovery (M4.0), against the official vectors.

The Trezor reference vectors (entropy, mnemonic, seed with passphrase "TREZOR")
are the primary oracle; the BIP-32 root xprv is checked via keylab.hd.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import mnemonic as m
from keylab.hd import ExtendedKey

FAST = settings(max_examples=50, deadline=None)

_VEC = Path(__file__).parent / "vectors" / "bip39_trezor_vectors.json"
_DATA = json.loads(_VEC.read_text(encoding="utf-8"))
VECTORS = _DATA["english"]          # [entropy_hex, mnemonic, seed_hex, bip32_root_xprv]
PASSPHRASE = _DATA["passphrase"]    # "TREZOR"
VECTOR_IDS = [f"ent{len(bytes.fromhex(v[0])) * 8}-{i}" for i, v in enumerate(VECTORS)]

CANONICAL_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


# --- wordlist integrity -------------------------------------------------------------------------

def test_wordlist_is_the_official_2048_word_english_list() -> None:
    assert len(m.ENGLISH_WORDLIST) == 2048
    assert len(set(m.ENGLISH_WORDLIST)) == 2048
    assert m.ENGLISH_WORDLIST[0] == "abandon" and m.ENGLISH_WORDLIST[-1] == "zoo"
    assert m.ENGLISH_WORDLIST == tuple(sorted(m.ENGLISH_WORDLIST))  # BIP-39 list is sorted
    joined = ("\n".join(m.ENGLISH_WORDLIST) + "\n").encode()
    assert hashlib.sha256(joined).hexdigest() == CANONICAL_WORDLIST_SHA256


def test_vector_words_are_all_in_the_wordlist() -> None:
    for _entropy, phrase, _seed, _xprv in VECTORS:
        for word in phrase.split():
            assert word in m.ENGLISH_WORDLIST


# --- official vectors ---------------------------------------------------------------------------

@pytest.mark.parametrize("entropy_hex,phrase,seed_hex,root_xprv", VECTORS, ids=VECTOR_IDS)
def test_official_vector_all_stages(entropy_hex, phrase, seed_hex, root_xprv) -> None:
    entropy = bytes.fromhex(entropy_hex)
    assert m.entropy_to_mnemonic(entropy) == phrase            # entropy -> mnemonic
    assert m.mnemonic_to_entropy(phrase) == entropy            # mnemonic -> entropy
    seed = m.mnemonic_to_seed(phrase, PASSPHRASE)
    assert seed.hex() == seed_hex                              # mnemonic -> seed
    assert ExtendedKey.from_seed(seed).serialize() == root_xprv  # seed -> BIP-32 root


def test_seed_matches_keylab_hd_implementation() -> None:
    from keylab.hd import mnemonic_to_seed as hd_seed
    for _entropy, phrase, _seed, _xprv in VECTORS[:5]:
        assert m.mnemonic_to_seed(phrase, PASSPHRASE) == hd_seed(phrase, PASSPHRASE)


# --- round trips --------------------------------------------------------------------------------

@pytest.mark.parametrize("bits", m.VALID_ENTROPY_BITS)
def test_entropy_round_trip_boundary_sizes(bits: int) -> None:
    import secrets
    for _ in range(20):
        entropy = secrets.token_bytes(bits // 8)
        phrase = m.entropy_to_mnemonic(entropy)
        assert len(phrase.split()) == bits // 32 * 3  # 12/15/18/21/24
        assert m.mnemonic_to_entropy(phrase) == entropy
        assert m.is_valid_mnemonic(phrase)


def test_generate_mnemonic_is_valid_and_fresh() -> None:
    seen = set()
    for bits in m.VALID_ENTROPY_BITS:
        phrase = m.generate_mnemonic(bits)
        assert m.is_valid_mnemonic(phrase)
        assert len(phrase.split()) == bits // 32 * 3
        seen.add(phrase)
    assert len(seen) == len(m.VALID_ENTROPY_BITS)  # different sizes differ
    assert m.generate_mnemonic(128) != m.generate_mnemonic(128)  # random


# --- checksum / malformed input -----------------------------------------------------------------

def test_altered_checksum_word_is_rejected() -> None:
    phrase = VECTORS[0][1]                       # "abandon ... about"
    words = phrase.split()
    # Replace the final (checksum) word with another valid word -> checksum fails.
    for replacement in ("abandon", "zoo", "ability"):
        if replacement != words[-1]:
            altered = " ".join(words[:-1] + [replacement])
            assert not m.is_valid_mnemonic(altered)
            with pytest.raises(ValueError, match="checksum"):
                m.mnemonic_to_entropy(altered)


def test_invalid_words_are_rejected() -> None:
    phrase = VECTORS[0][1].split()
    phrase[5] = "notaword"
    with pytest.raises(ValueError, match="not in the BIP-39 English list"):
        m.mnemonic_to_entropy(" ".join(phrase))
    assert not m.is_valid_mnemonic(" ".join(phrase))


@pytest.mark.parametrize("count", [0, 1, 11, 13, 14, 23, 25, 48])
def test_wrong_word_counts_are_rejected(count: int) -> None:
    phrase = " ".join(["abandon"] * count)
    with pytest.raises(ValueError, match="words"):
        m.mnemonic_to_entropy(phrase)
    assert not m.is_valid_mnemonic(phrase)


def test_empty_input() -> None:
    assert not m.is_valid_mnemonic("")
    assert not m.is_valid_mnemonic("   ")
    with pytest.raises(ValueError):
        m.mnemonic_to_entropy("")
    # The seed function does not validate; it is defined for any string.
    assert len(m.mnemonic_to_seed("", "")) == 64


# --- whitespace / Unicode normalization ---------------------------------------------------------

def test_whitespace_normalization() -> None:
    entropy = bytes.fromhex(VECTORS[0][0])
    phrase = VECTORS[0][1]
    messy = "   " + phrase.replace(" ", "   ") + "\t\n "   # leading/trailing/repeat/tabs
    assert m.normalize_mnemonic(messy) == phrase
    assert m.mnemonic_to_entropy(messy) == entropy


def test_unicode_nfkd_normalization_of_passphrase() -> None:
    # NFKD-equivalent passphrases must give the same seed (BIP-39 normalizes NFKD).
    phrase = VECTORS[0][1]
    composed = "é"          # e-acute, precomposed
    decomposed = "é"       # e + combining acute
    assert unicodedata.normalize("NFKD", composed) == unicodedata.normalize("NFKD", decomposed)
    assert m.mnemonic_to_seed(phrase, composed) == m.mnemonic_to_seed(phrase, decomposed)


def test_passphrase_changes_seed_but_not_entropy() -> None:
    phrase = VECTORS[0][1]
    assert m.mnemonic_to_seed(phrase, "") != m.mnemonic_to_seed(phrase, "TREZOR")
    assert m.mnemonic_to_entropy(phrase) == bytes.fromhex(VECTORS[0][0])  # entropy independent of passphrase


# --- type errors --------------------------------------------------------------------------------

def test_type_and_size_errors() -> None:
    with pytest.raises(ValueError, match="bits"):
        m.generate_entropy(129)
    with pytest.raises(ValueError, match="bits"):
        m.entropy_to_mnemonic(b"\x00" * 15)     # 120 bits: not a valid size
    with pytest.raises(TypeError):
        m.entropy_to_mnemonic("not bytes")
    with pytest.raises(TypeError):
        m.mnemonic_to_entropy(1234)


# --- Hypothesis / invariants --------------------------------------------------------------------

@given(st.sampled_from(m.VALID_ENTROPY_BITS), st.integers(0, 2**256 - 1))
@FAST
def test_random_entropy_round_trips(bits: int, value: int) -> None:
    entropy = (value % (1 << bits)).to_bytes(bits // 8, "big")
    phrase = m.entropy_to_mnemonic(entropy)
    assert m.mnemonic_to_entropy(phrase) == entropy
    assert m.is_valid_mnemonic(phrase)


@given(st.integers(0, 2**128 - 1))
@FAST
def test_mnemonic_is_twelve_known_words_for_128_bit(value: int) -> None:
    phrase = m.entropy_to_mnemonic(value.to_bytes(16, "big"))
    words = phrase.split()
    assert len(words) == 12
    assert all(w in m.ENGLISH_WORDLIST for w in words)


@given(st.binary(min_size=16, max_size=16))
@FAST
def test_seed_is_64_bytes_and_deterministic(entropy: bytes) -> None:
    phrase = m.entropy_to_mnemonic(entropy)
    seed1 = m.mnemonic_to_seed(phrase, "pass")
    seed2 = m.mnemonic_to_seed(phrase, "pass")
    assert seed1 == seed2 and len(seed1) == 64


# --- correctness-gated benchmark --------------------------------------------------------------

def test_benchmark_mnemonic_is_correctness_gated() -> None:
    from keylab.benchmarks import benchmark_mnemonic

    report = benchmark_mnemonic(count=10, bits=128)
    assert report["benchmark"] == "bip39-mnemonic"
    assert report["outputs_round_trip"] is True
    assert set(report["timings_us_per_op"]) == {
        "entropy_to_mnemonic_us", "mnemonic_to_entropy_us", "mnemonic_to_seed_us"
    }
    with pytest.raises(ValueError):
        benchmark_mnemonic(count=0)
    with pytest.raises(ValueError):
        benchmark_mnemonic(bits=100)
