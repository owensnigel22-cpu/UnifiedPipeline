from __future__ import annotations

import json

from keylab.cli import main
from keylab.hashes.reduced import ripemd160_reduced, sha256_reduced
from keylab.sat.cnf import CNF
from keylab.sat.diagnostics import formula_diagnostics


def test_formula_diagnostics_reports_clause_structure_without_claiming_bcp() -> None:
    formula = CNF()
    first = formula.constant(True)
    second = formula.fresh_var()
    formula.add_clause(first)
    formula.add_clause(second, -first)
    formula.add_clause()

    assert formula_diagnostics(formula) == {
        "variables": 2,
        "clauses": 4,
        "total_literals": 4,
        "average_clause_width": 1.0,
        "maximum_clause_width": 2,
        "unit_clauses": 2,
        "empty_clauses": 1,
        "constant_variables": 1,
        "propagation_strength": "not measured; requires solver propagation statistics",
    }


def test_sha_cli_exports_formula_diagnostics(tmp_path, capsys) -> None:
    report_path = tmp_path / "sat_report.json"
    assert main(
        [
            "sha256-cnf",
            "--target",
            sha256_reduced(b"A", rounds=1).hex(),
            "--rounds",
            "1",
            "--message-length",
            "1",
            "--output",
            str(tmp_path / "sha.cnf"),
            "--diagnostics-output",
            str(report_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert metrics["formula_diagnostics"] == report
    assert report["variables"] == metrics["variables"]
    assert report["propagation_strength"].startswith("not measured")


def test_ripemd_cli_exports_formula_diagnostics(tmp_path, capsys) -> None:
    report_path = tmp_path / "ripemd-report.json"
    assert main(
        [
            "ripemd160-cnf",
            "--target",
            ripemd160_reduced(b"A", steps=1).hex(),
            "--message-length",
            "1",
            "--steps",
            "1",
            "--output",
            str(tmp_path / "ripemd.cnf"),
            "--diagnostics-output",
            str(report_path),
        ]
    ) == 0

    metrics = json.loads(capsys.readouterr().err)
    assert metrics["formula_diagnostics"]["clauses"] == metrics["clauses"]
    assert report_path.is_file()
