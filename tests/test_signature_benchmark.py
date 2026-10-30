import json
from importlib.util import find_spec

import pytest

from keylab.benchmarks import SIGNATURE_OPERATIONS, benchmark_signatures
from keylab.cli import main


def test_signature_benchmark_covers_every_operation_without_secrets() -> None:
    report = benchmark_signatures(count=2, repetitions=1, backend="keylab")
    rows = report["operations"]
    assert [row["operation"] for row in rows] == list(SIGNATURE_OPERATIONS)
    assert {row["implementation"] for row in rows} == {"keylab"}
    assert all(row["median_ops_per_second"] > 0 and len(row["samples_ms"]) == 1 for row in rows)
    serialized = json.dumps(report)
    for forbidden in ("scalar\"", "private", "signature\""):
        assert forbidden not in serialized
    assert report["keylab_multiplication"].startswith("auto:")


def test_signature_benchmark_adds_libsecp256k1_reference_rows_when_available() -> None:
    if find_spec("coincurve") is None:
        pytest.skip("coincurve is not installed")
    report = benchmark_signatures(count=2, repetitions=1, backend="all")
    reference_ops = {row["operation"] for row in report["operations"] if row["implementation"] == "libsecp256k1"}
    assert reference_ops == {"schnorr-sign", "schnorr-verify", "ecdsa-sign", "ecdsa-verify"}


@pytest.mark.parametrize("kwargs", [{"count": 0}, {"seed": -1}, {"repetitions": 0}, {"backend": "gpu"}])
def test_signature_benchmark_rejects_invalid_parameters(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        benchmark_signatures(**kwargs)  # type: ignore[arg-type]


def test_signature_benchmark_cli_table_and_json(capsys) -> None:
    assert main(["benchmark-signatures", "--count", "1", "--repetitions", "1", "--backend", "keylab"]) == 0
    table = capsys.readouterr().out
    assert "taproot-sign" in table and "Keylab point multiplication" in table
    assert main(["benchmark-signatures", "--count", "1", "--repetitions", "1", "--backend", "keylab",
                 "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["benchmark"] == "secp256k1-signatures-bip32-taproot"
