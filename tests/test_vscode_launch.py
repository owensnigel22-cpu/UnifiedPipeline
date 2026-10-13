import json
from pathlib import Path

import pytest

from keylab import cli
from keylab.cli import main
from keylab.sat.solver import SOLVER_CANDIDATES, find_solver


def test_selftest_includes_hash_reference_vectors(capsys) -> None:
    assert main(["selftest"]) == 0

    output = capsys.readouterr().out
    assert "PASS SHA-256 reference vector" in output
    assert "PASS RIPEMD-160 reference vector" in output
    assert "PASS toy RSA modular exponentiation round-trip" in output
    assert "PASS SHA-256 length-extension reference" in output


def test_sat_selftest_runs_sat_and_unsat_formulas(capsys) -> None:
    if not any(find_solver((name,)) for name in SOLVER_CANDIDATES):
        pytest.skip("no supported external SAT solver is installed")

    assert main(["sat-selftest", "--timeout", "10"]) == 0

    output = capsys.readouterr().out
    assert "SAT=SATISFIABLE" in output
    assert "UNSAT=UNSATISFIABLE" in output


def test_sat_selftest_reports_missing_optional_solver(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "find_solver", lambda candidates: None)

    assert main(["sat-selftest"]) == 0
    assert "SKIP no supported SAT solver found on PATH" in capsys.readouterr().out


def test_vscode_launch_configurations_call_supported_cli_commands(tmp_path, capsys) -> None:
    project_root = Path(__file__).resolve().parents[1]
    launch_file = project_root / ".vscode" / "launch.json"
    configurations = json.loads(launch_file.read_text(encoding="utf-8"))["configurations"]
    assert len(configurations) == 11

    cli_configurations = [item for item in configurations if item["module"] == "keylab.cli"]
    assert len(cli_configurations) == 8
    benchmark_configuration = next(
        item for item in cli_configurations if item["name"].startswith("SHA-256 CNF Benchmark")
    )
    assert benchmark_configuration["args"][-2:] == ["--end-round", "16"]
    cube_configuration = next(
        item
        for item in cli_configurations
        if item["name"].startswith("SHA-256 CNF Cube-and-Conquer")
    )
    assert cube_configuration["args"][-6:] == [
        "--solver",
        "kissat",
        "--cube-depth",
        "4",
        "--parallel-workers",
        "4",
    ]
    throughput_configuration = next(
        item
        for item in configurations
        if item["name"].startswith("Benchmark: Multi-Core Scaling")
    )
    assert throughput_configuration["module"] == "keylab.sat.benchmark_throughput"
    assert throughput_configuration["args"][-6:] == [
        "1",
        "2",
        "4",
        "8",
        "--csv-output",
        "${workspaceFolder}/scaling_results.csv",
    ]
    profile_configuration = next(
        item for item in configurations if item["name"] == "Profile SAT Throughput"
    )
    assert profile_configuration["module"] == "cProfile"
    assert profile_configuration["args"][:3] == [
        "-o",
        "${workspaceFolder}/sat-throughput.prof",
        "-m",
    ]
    stage_four_configuration = next(
        item
        for item in cli_configurations
        if item["name"].startswith("SHA-256 Known-Input SAT Verification")
    )
    assert stage_four_configuration["args"] == [
        "hash-cnf-selftest",
        "--hash",
        "sha256",
        "--rounds",
        "16",
        "18",
        "20",
        "22",
        "24",
    ]
    for configuration in cli_configurations:
        if configuration in (cube_configuration, stage_four_configuration):
            continue
        assert configuration["module"] == "keylab.cli"
        assert configuration["type"] == "debugpy"
        args = [
            argument.replace("${workspaceFolder}", str(tmp_path))
            for argument in configuration["args"]
        ]
        assert main(args) == 0
        capsys.readouterr()

    assert (tmp_path / "sha256_16r.cnf").is_file()
    assert (tmp_path / "ripemd160_16s.cnf").is_file()

    pytest_configuration = next(
        item for item in configurations if item["module"] == "pytest"
    )
    assert pytest_configuration["args"] == [
        "tests/test_rsa.py",
        "tests/test_ripemd160_cnf.py",
        "-v",
    ]
