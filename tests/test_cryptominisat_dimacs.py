from io import StringIO

import pytest

from keylab.sat.cryptominisat import CryptoMiniSatFormula, literal_value


def test_mixed_native_xor_export_and_rhs_format() -> None:
    formula = CryptoMiniSatFormula(variable_count=4)
    formula.add_clause((1, 2))
    formula.add_clause((-3, 4))
    formula.add_xor((1, 2, 3), True)
    formula.add_xor((1, 2, 4), False)
    output = StringIO()
    formula.write_dimacs(output)
    assert output.getvalue() == "p cnf 4 4\n1 2 0\n-3 4 0\nx 1 2 3 0\nx -1 2 4 0\n"


def test_xor_duplicate_variables_cancel_and_empty_false_is_omitted() -> None:
    formula = CryptoMiniSatFormula(variable_count=2)
    formula.add_xor((1, 1, 2), True)
    formula.add_xor((), False)
    output = StringIO()
    formula.write_dimacs(output)
    assert output.getvalue() == "p cnf 2 1\nx 2 0\n"


def test_signed_literal_evaluator_checks_bounds_and_sign() -> None:
    assert literal_value([False, True, False], 1)
    assert literal_value([False, False, False], -1)
    with pytest.raises(ValueError):
        literal_value([False], 1)
