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
    FeatureEvidence("BIP49 P2SH-P2WPKH address encoding", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Address encoding; HD account-path derivation is listed separately."),
    FeatureEvidence("BIP84 P2WPKH address encoding", "src/keylab/encoding/address.py", "tests/test_address.py", notes="Address encoding; HD account-path derivation is listed separately."),
    FeatureEvidence("BIP49 and BIP84 HD account-path derivation", "src/keylab/hd.py", "tests/test_bip32_vectors.py", notes="Checked against the official BIP-49 (testnet uprv/upub) and BIP-84 (zprv/zpub) vectors."),
    FeatureEvidence("BIP32 extended keys: xprv/xpub, CKDpub, fingerprints, parent identifiers", "src/keylab/hd.py", "tests/test_bip32_vectors.py", notes="Official BIP-32 test vectors 1-4 (17 chains) and all 16 invalid keys of vector 5; SLIP-132 y/z/u/v families."),
    FeatureEvidence("BIP-340 official vectors 0-18 with variable-length messages", "src/keylab/ec/schnorr.py", "tests/test_bip340_vectors.py", "keylab benchmark-signatures", "Signing and verification for every official vector, including the 2022 variable-length messages."),
    FeatureEvidence("BIP-327 MuSig2 KeyAgg, KeySort, and tweaking", "src/keylab/ec/musig2.py", "tests/test_musig2.py", notes="Public-key aggregation only; nonce generation and partial signing are deliberately not implemented. Legacy pre-BIP-327 behaviour is kept behind mode='legacy-xonly' in the advanced suite."),
    FeatureEvidence("BIP-341 key-path signing, tweaked secret keys, and script-tree builder", "src/keylab/encoding/taproot.py", "tests/test_taproot_bip341.py", "keylab benchmark-signatures", "All official BIP-341 wallet vectors: 7 scriptPubKey/tree cases and 7 key-path spends."),
    FeatureEvidence("BIP-341 signature message and sighash", "src/keylab/encoding/transaction.py", "tests/test_taproot_bip341.py", notes="Supports every hash type, annex, and the BIP-342 script-path extension; no consensus or script execution."),
    FeatureEvidence("BIP-143 witness-v0 (SegWit v0) signature hash", "src/keylab/encoding/transaction.py", "tests/test_bip143_sighash.py", "keylab benchmark (bip143-sighash)", notes="All official vectors (P2WPKH, P2SH-P2WPKH, P2WSH, P2SH-P2WSH, No-FindAndDelete): hashPrevouts/hashSequence/hashOutputs, full preimage, and sighash for every hash type, incl. OP_CODESEPARATOR and SINGLE-with-no-output. Caller supplies the reduced scriptCode; no consensus or Script execution."),
    FeatureEvidence("Differential ECC tests against libsecp256k1 and fastecdsa", "src/keylab/ec/secp256k1.py", "tests/test_ecc_differential.py", notes="Skipped automatically when the reference library is not installed."),
    FeatureEvidence("Hypothesis secp256k1 group-law and encoding properties", "src/keylab/ec/secp256k1.py", "tests/test_ecc_properties.py"),
    FeatureEvidence("Shared lift_x, square-root, and curve-validation helpers", "src/keylab/ec/secp256k1.py", "tests/test_ec_helpers.py"),
    FeatureEvidence("Division polynomials and multiplication-by-n x formula", "src/keylab/ec/division_polynomials.py", "tests/test_ec_research.py", notes="Research module; verified against scalar multiplication on secp256k1 and toy curves."),
    FeatureEvidence("Doubling-quartic inversion over F_p", "src/keylab/ec/quartic.py", "tests/test_ec_research.py", notes="Research module; gives no discrete-log advantage."),
    FeatureEvidence("Point halving and doubling preimages", "src/keylab/ec/halving.py", "tests/test_ec_research.py", notes="Halving equals multiplication by (N+1)/2; it transforms but never reveals a discrete logarithm."),
    FeatureEvidence("Signature, BIP32, Taproot, and MuSig2 benchmark", "src/keylab/benchmarks.py", "tests/test_signature_benchmark.py", "keylab benchmark-signatures", "Seeded corpus, correctness gate, randomized order, medians; methodology and recorded results in docs/benchmarks.md."),
    FeatureEvidence("BIP-39 seed derivation against the Trezor reference vectors", "src/keylab/hd.py", "tests/test_bip39_vectors.py", notes="All 24 English vectors (seed and BIP-32 root xprv)."),
    FeatureEvidence("BIP-39 mnemonic generation, validation, and recovery (English)", "src/keylab/mnemonic.py", "tests/test_mnemonic.py", notes="Entropy<->mnemonic<->seed for 128/160/192/224/256-bit entropy; checksum and word-list validation; all 24 official vectors both directions. Generated mnemonics are for study, not real funds (see SECURITY.md)."),
    FeatureEvidence("BIP-39 mnemonic benchmark", "src/keylab/benchmarks.py", "tests/test_mnemonic.py", notes="Correctness-gated (round-trip) timings for entropy->mnemonic, mnemonic->entropy, mnemonic->seed; metrics only."),
    FeatureEvidence("Bech32/Bech32m official vectors (BIP-173, BIP-350)", "src/keylab/encoding/bech32.py", "tests/test_bech32_vectors.py", notes="Valid/invalid checksums and addresses; BIP-173 v1+ Bech32 addresses are rejected per BIP-350."),
    FeatureEvidence("BIP-341 control-block length and leaf-version limits", "src/keylab/encoding/taproot.py", "tests/test_taproot_limits.py", notes="At most 128 Merkle nodes; leaf version 0x50 is reserved for the annex."),
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
        "evidence": "Official BIP-86 root, account, receive, and change vectors in tests/test_bip32_vectors.py; no persisted BIP-86 benchmark result.",
    },
    "bip340": {
        "implemented": True,
        "tested": True,
        "benchmarked": True,
        "evidence": "All 19 official BIP-340 vectors (tests/test_bip340_vectors.py) and libsecp256k1 cross-checks; benchmark recorded in docs/benchmarks.md.",
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
    "bip327_key_agg": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Official BIP-327 key_agg and key_sort vectors, including error cases, in tests/test_musig2.py.",
    },
    "bip32_official_vectors": {
        "implemented": True,
        "tested": True,
        "benchmarked": True,
        "evidence": "BIP-32 vectors 1-5 plus BIP-49/84/86 in tests/test_bip32_vectors.py; CKDpriv/CKDpub timings in docs/benchmarks.md.",
    },
    "bip341_sighash_and_key_path_signing": {
        "implemented": True,
        "tested": True,
        "benchmarked": True,
        "evidence": "Official BIP-341 wallet vectors in tests/test_taproot_bip341.py; tweak/sign timings in docs/benchmarks.md.",
    },
    "point_halving_research": {
        "implemented": True,
        "tested": True,
        "benchmarked": False,
        "evidence": "Deterministic secp256k1 and toy-curve tests in tests/test_ec_research.py; no discrete-log advantage is claimed.",
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
