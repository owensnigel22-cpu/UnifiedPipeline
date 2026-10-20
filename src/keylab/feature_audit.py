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
    FeatureEvidence("BIP39 seed and BIP32 derivation", "src/keylab/hd.py", "tests/test_hd.py"),
    FeatureEvidence("BIP86 Taproot key-path derivation", "src/keylab/hd.py", "tests/test_hd.py", notes="BIP86 key-path output; this does not claim script-path wallet derivation."),
    FeatureEvidence("SEC1 compressed and uncompressed public-key serialization", "src/keylab/ec/sec1.py", "tests/test_schnorr.py"),
    FeatureEvidence("BIP-340 Schnorr signatures", "src/keylab/ec/schnorr.py", "tests/test_schnorr.py"),
    FeatureEvidence("Taproot script tree and control blocks", "src/keylab/encoding/taproot.py", "tests/test_taproot.py"),
    FeatureEvidence("secp256k1 GLV experimental multiplier", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", "keylab benchmark-pubkey --backend all", "Experimental Python implementation; benchmark before choosing it."),
    FeatureEvidence("fixed-base width-5 wNAF multiplier", "src/keylab/ec/secp256k1.py", "tests/test_secp256k1.py", "keylab benchmark-pubkey --backend all", "Experimental Python implementation; compare on the current machine."),
    FeatureEvidence("SHA-256 CNF model and known-input solve verification", "src/keylab/hashes/sha256_cnf.py", "tests/test_sha256_cnf.py", "keylab hash-cnf-selftest"),
    FeatureEvidence("SHA-256 CNF XOR encoding comparison", "src/keylab/hashes/sha256_cnf.py", "tests/test_sha256_cnf.py", "keylab sha256-cnf-benchmark"),
    FeatureEvidence("Parallel SAT cube solving", "src/keylab/sat/parallel.py", "tests/test_parallel_sat.py", "keylab sat-throughput-benchmark"),
    FeatureEvidence("Native CryptoMiniSat XOR DIMACS export", "src/keylab/sat/cryptominisat.py", "tests/test_cryptominisat_dimacs.py"),
    FeatureEvidence("RFC 5869 HKDF-SHA256/SHA512", "src/keylab/crypto.py", "tests/test_hkdf.py"),
    FeatureEvidence("Walkback SHA-256 state trace", "src/keylab/hashes/reduced.py", "tests/test_hashes.py"),
)


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


__all__ = ["FeatureEvidence", "feature_audit"]
