"""Structural CNF metrics; propagation behavior requires executing a solver."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict

from keylab.sat.cnf import CNF


class FormulaDiagnostics(TypedDict):
    variables: int
    clauses: int
    total_literals: int
    average_clause_width: float
    maximum_clause_width: int
    unit_clauses: int
    empty_clauses: int
    constant_variables: int
    propagation_strength: str


def formula_diagnostics(formula: CNF) -> FormulaDiagnostics:
    """Measure formula structure without claiming to measure propagation strength."""
    clause_widths = [len(clause) for clause in formula.clauses]
    clause_count = len(formula.clauses)
    return {
        "variables": formula.variable_count,
        "clauses": clause_count,
        "total_literals": sum(clause_widths),
        "average_clause_width": (
            sum(clause_widths) / clause_count if clause_count else 0.0
        ),
        "maximum_clause_width": max(clause_widths, default=0),
        "unit_clauses": sum(width == 1 for width in clause_widths),
        "empty_clauses": sum(width == 0 for width in clause_widths),
        "constant_variables": len(formula._constant_values),
        "propagation_strength": "not measured; requires solver propagation statistics",
    }


def write_formula_diagnostics(formula: CNF, output: str | Path) -> FormulaDiagnostics:
    """Write structural formula metrics as JSON and return the emitted report."""
    report = formula_diagnostics(formula)
    Path(output).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report
