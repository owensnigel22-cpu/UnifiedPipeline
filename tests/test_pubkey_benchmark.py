import pytest

from keylab.benchmarks import (
    benchmark_hash160_only,
    benchmark_multiple_wifs,
    benchmark_synthetic_wifs,
    benchmark_wif_to_pubkey,
)
from keylab.cli import main
from keylab.encoding.wif import encode as encode_wif


def test_wif_to_pubkey_benchmark_reports_stages_and_verified_result() -> None:
    report = benchmark_wif_to_pubkey(4, warmup=1, backend="python")
    assert report["iterations"] == 4
    assert report["reference_pubkey_hex"] == (
        "024f8ad6f64980c2926c32836e10f00a7752ea88ce41db37e789db2cec48bc0b64"
    )
    assert "Machine-dependent" in report["measurement_note"]
    assert set(report["stages_ms"]) == {
        "wif_decode", "scalar_parse", "scalar_multiplication", "compression", "hex_encoding"
    }
    assert "wif" not in report
    assert "private_scalar" not in report


def test_wif_to_pubkey_benchmark_rejects_invalid_iteration_counts() -> None:
    with pytest.raises(ValueError, match="iterations"):
        benchmark_wif_to_pubkey(0)


def test_affine_window_backend_matches_benchmark_reference() -> None:
    report = benchmark_wif_to_pubkey(3, warmup=1, backend="python-affine-window")
    assert report["backend"] == "python-affine-window"
    assert report["throughput_per_second"] > 0


def test_benchmark_pubkey_cli_emits_json(capsys) -> None:
    assert main(["benchmark-pubkey", "--iterations", "2", "--warmup", "0", "--backend", "python"]) == 0
    output = capsys.readouterr().out
    assert '"benchmark": "wif-to-compressed-pubkey"' in output
    assert '"iterations": 2' in output


def test_multiple_wif_benchmark_runs_full_pipeline_without_returning_secrets() -> None:
    wifs = (encode_wif(1), encode_wif(2))
    report = benchmark_multiple_wifs(wifs, backend="python", warmup=0)
    assert report["keys_processed"] == 2
    assert report["addresses_derived"] == 8
    assert report["corpus_source"] == "provided"
    assert set(report["stages_ms"]) == {
        "wif_decode", "scalar_parse", "scalar_multiplication", "serialization", "address_generation"
    }
    assert set(report["address_types_ms"]) == {"p2pkh", "p2sh_p2wpkh", "p2wpkh", "p2tr"}
    assert all(value >= 0 for value in report["address_types_ms"].values())
    serialized = str(report)
    assert all(wif not in serialized for wif in wifs)
    assert "private_scalar" not in serialized


def test_synthetic_wif_benchmark_counts_without_address_generation() -> None:
    report = benchmark_synthetic_wifs(2, backend="python", derive_addresses=False, warmup=0)
    assert report["corpus_source"] == "synthetic-random"
    assert report["keys_processed"] == 2
    assert report["addresses_derived"] is None


def test_multiple_wif_benchmark_can_time_one_address_family() -> None:
    report = benchmark_multiple_wifs(
        (encode_wif(1), encode_wif(2)),
        backend="python",
        warmup=0,
        address_types=("p2wpkh",),
    )
    assert report["addresses_derived"] == 2
    assert report["address_types_selected"] == ["p2wpkh"]
    assert report["address_counts"] == {
        "p2pkh": 0,
        "p2sh_p2wpkh": 0,
        "p2wpkh": 2,
        "p2tr": 0,
    }
    assert report["address_types_us_per_address"]["p2wpkh"] is not None


def test_multi_wif_cli_emits_aggregate_json(capsys) -> None:
    assert main([
        "benchmark-wifs", "--count", "2", "--warmup", "0", "--backend", "python", "--no-addresses"
    ]) == 0
    output = capsys.readouterr().out
    assert '"keys_processed": 2' in output
    assert '"scalar_multiplication"' in output


def test_hash160_only_benchmark_reports_hash_throughput_without_keys() -> None:
    report = benchmark_hash160_only(3, backend="python")
    assert report["keys_processed"] == 3
    assert report["digest_bytes_checked"] == 60
    assert report["throughput_per_second"] > 0
    assert report["setup_ms_excluded_from_hash_timing"] >= 0


def test_benchmark_pubkey_accepts_count_alias(capsys) -> None:
    assert main(["benchmark-pubkey", "--count", "2", "--warmup", "0", "--backend", "auto"]) == 0
    assert '"iterations": 2' in capsys.readouterr().out


def test_hash160_cli_emits_json(capsys) -> None:
    assert main(["benchmark-hash160", "--count", "3", "--backend", "python"]) == 0
    output = capsys.readouterr().out
    assert '"keys_processed": 3' in output
    assert '"benchmark": "hash160-compressed-public-keys"' in output
