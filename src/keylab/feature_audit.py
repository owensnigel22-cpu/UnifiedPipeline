"""Evidence-oriented feature inventory for the Keylab package."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class FeatureEvidence:
    """File-level evidence without claiming tests passed or benchmarks ran."""

    feature: str
    implementation: str
    test_source: str | None = None
    benchmark_command: str | None = None
    notes: str = ""


_FEATURES = (
    FeatureEvidence("WIF parsing and checksums", "src/keylab/encoding/wif.py", "tests/test_wif.py"),
    FeatureEvidence("WIF to address derivation", "src/keylab/encoding/address.py", "tests/test_address.py"),
    FeatureEvidence("WIF-to-address correspondence verification", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Derives candidate addresses from a WIF and reports exact matching address types; does not recover keys from addresses."),
    FeatureEvidence("BIP39 mnemonic-to-seed derivation", "src/keylab/hd.py", "tests/test_hd.py"),
    FeatureEvidence("BIP32 private child/path derivation", "src/keylab/hd.py", "tests/test_hd.py"),
    FeatureEvidence("BIP32 unhardened parent recovery demonstration", "src/keylab/hd.py", "tests/test_hd.py", notes="Requires the compromised child private key plus parent chain code/public key; hardened edges are not recoverable by this operation."),
    FeatureEvidence("BIP44 P2PKH HD derivation", "src/keylab/hd.py", "tests/test_hd.py"),
    FeatureEvidence("BIP86 Taproot key-path derivation", "src/keylab/hd.py", "tests/test_hd.py", notes="BIP86 key-path output; this does not claim script-path wallet derivation."),
    FeatureEvidence("BIP49 P2SH-P2WPKH address encoding", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Address encoding is supported; a BIP49 HD account-path derivation API is not currently claimed."),
    FeatureEvidence("BIP84 P2WPKH address encoding", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Address encoding is supported; a BIP84 HD account-path derivation API is not currently claimed."),
    FeatureEvidence("SEC1 compressed, uncompressed, and x-only public-key serialization", "src/keylab/ec/sec1.py", "tests/test_schnorr.py"),
    FeatureEvidence("BIP-340 Schnorr signatures", "src/keylab/ec/schnorr.py", "tests/test_schnorr.py"),
    FeatureEvidence("Taproot script tree and control blocks", "src/keylab/encoding/taproot.py", "tests/test_taproot.py"),
    FeatureEvidence("secp256k1 GLV experimental multiplier", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", "keylab benchmark-pubkey --backend all", "Experimental Python implementation; benchmark before choosing it."),
    FeatureEvidence("secp256k1 GLV decomposition and group-level multiplication check", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", notes="Tests compare kG with the joint GLV path; decomposition identity alone is not treated as sufficient."),
    FeatureEvidence("fixed-base width-5 wNAF multiplier", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", "keylab benchmark-pubkey --backend all", "Experimental Python implementation; compare on the current machine."),
    FeatureEvidence("candidate public-key to address consistency check", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Forward candidate verification only; does not recover a public key from an address."),
    FeatureEvidence("BIP-340 official signing known-answer vector", "src/keylab/ec/schnorr.py", "tests/test_schnorr.py"),
    FeatureEvidence("RFC 6979 deterministic ECDSA nonce generation", "src/keylab/ec/secp256k1.py", "tests/test_advanced_suite.py", notes="The advanced suite retains a nonce derivation trace for educational inspection."),
    FeatureEvidence("Taproot tweak multiplication backend dispatch", "src/keylab/encoding/taproot.py", "tests/test_taproot.py", "keylab benchmark-wifs --backend coincurve --addresses p2tr", "Generator multiplication uses native backends when installed, otherwise the fixed-base window table; point addition remains affine Python."),
    FeatureEvidence("reproducible ECC backend benchmark", "src/keylab/benchmarks.py", "tests/test_pubkey_benchmark.py", "keylab benchmark-ec", "Uses a shared seeded scalar corpus, correctness checks, warmup exclusion, randomized method order, and median timings; v65 window algorithm is ported for comparison."),
    FeatureEvidence("SHA-256 CNF model and known-input solve verification", "src/keylab/hashes/sha256_cnf.py", "tests/test_sha256_cnf.py", "keylab hash-cnf-selftest"),
    FeatureEvidence("reduced-round symbolic SHA-256 SAT roundtrip", "src/keylab/hashes/sha256_cnf.py", "tests/test_feature_audit.py", "keylab sha256-symbolic-roundtrip", "A circuit/solver wiring test, not full SHA-256 inversion."),
    FeatureEvidence("SHA-256 CNF XOR encoding comparison", "src/keylab/hashes/sha256_cnf.py", "tests/test_sha256_cnf.py", "keylab sha256-cnf-benchmark"),
    FeatureEvidence("Parallel SAT cube solving", "src/keylab/sat/parallel.py", "tests/test_parallel_sat.py", "keylab sat-throughput-benchmark"),
    FeatureEvidence("Native CryptoMiniSat XOR DIMACS export", "src/keylab/sat/cryptominisat.py", "tests/test_cryptominisat_dimacs.py"),
    FeatureEvidence("BitVec32 concrete folding and symbolic ADD32", "src/keylab/sat/bitvec32.py", "tests/test_bitvec32.py", notes="Concrete operations allocate no CNF structure; symbolic addition is modulo 2^32 and discards carry-out."),
    FeatureEvidence("RFC 5869 HKDF-SHA256/SHA512", "src/keylab/crypto.py", "tests/test_hkdf.py"),
    FeatureEvidence("Bounded Pollard–Brent rho factor search", "src/keylab/numtheory/rsa.py", "tests/test_rsa.py", "keylab rsa-pollard-rho", "Probabilistic educational factorization with bounded iterations, restart limits, and batched GCD."),
    FeatureEvidence("Walkback SHA-256 state trace", "src/keylab/hashes/reduced.py", "tests/test_hashes.py"),
    FeatureEvidence("ECDSA nonce-reuse private-key recovery demonstration", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", notes="Candidate recovery is accepted only after public-key and both-signature verification."),
    FeatureEvidence("ECDSA public-key recovery candidates", "src/keylab/ec/ecdsa_recovery.py", "tests/test_ecdsa_recovery.py", notes="Returns only signature-verified public-key candidates; it does not recover private keys."),
    FeatureEvidence("ECDSA high-S signature detection", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", notes="Reports signature canonicality; it does not infer nonce quality."),
)

# Explicit repository status; these are evidence flags, not a claim that tests
# ran in the current environment.
FEATURE_STATUS = {
    "bip86": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "BIP-86 known-answer address test in tests/test_hd.py; no persisted BIP-86 benchmark result.",
    },
    "bip340": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "BIP-340 signing known-answer vector and tamper rejection in tests/test_schnorr.py; no persisted benchmark result.",
    },
    "bitvec32": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Concrete folding and symbolic ADD32 SAT roundtrip in tests/test_bitvec32.py; no persisted benchmark result.",
    },
    "wif_to_address": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Canonical scalar-1 WIF regression checks P2PKH, P2SH-P2WPKH, and P2WPKH in tests/test_address.py.",
    },
    "wif_address_verification": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Exact matching address type is tested against canonical P2PKH, P2SH-P2WPKH, and P2WPKH vectors, including uppercase Bech32.",
    },
    "bip32_unhardened_parent_recovery": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Requires the child private key plus parent xpub data and a non-hardened index; tests cover valid and invalid inputs.",
    },
    "ecdsa_public_key_recovery": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Signature-derived public-key candidates are verified against the digest/signature; does not recover private keys.",
    },
    "ecdsa_high_s_detection": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Detects non-low-S signature form; not a nonce-quality or RNG-bias detector.",
    },
    "address_type_benchmark": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "keylab benchmark-wifs --addresses p2pkh p2sh_p2wpkh p2wpkh p2tr --repetitions 5 reports per-type median timings; no persisted measurement.",
    },
    "rng_bias_from_r_values": {
        "implemented": False,
        "tested": False,
        "notes": "Observed ECDSA r values alone do not reveal nonce bits; no bias inference is claimed from r-only data.",
    },
    "rfc6979": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Deterministic signature known-answer and trace consistency tests; no persisted benchmark result.",
    },
    "taproot_tweak_fast_path": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Taproot uses scalar_mult(tweak, G, backend='auto') and affine point addition; Coincurve's full tweak-add experiment measured slower here. No persisted benchmark result.",
    },
    "partial_nonce_hnp": {
        "implemented": False,
        "tested": False,
        "vector_count": 0,
        "leaked_bits": None,
        "notes": "No partial-nonce HNP/lattice recovery implementation or validated test vectors are present.",
    },
}


def feature_audit() -> list[dict[str, object]]:
    """Return source evidence; test-source presence is not a test pass result."""
    package_root = Path(__file__).resolve().parents[1]
    repo_root = package_root.parent
    report: list[dict[str, object]] = []
    for feature in _FEATURES:
        row = asdict(feature)
        row["implementation_present"] = (repo_root / feature.implementation).is_file()
        row["test_source_present"] = (
            (repo_root / feature.test_source).is_file() if feature.test_source else None
        )
        row["benchmark_record"] = "not persisted; run the listed command to measure locally"
        report.append(row)
    return report


__all__ = ["FEATURE_STATUS", "FeatureEvidence", "feature_audit"]
