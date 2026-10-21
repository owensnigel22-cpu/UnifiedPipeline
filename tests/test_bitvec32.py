from keylab.sat import BitVec32
from keylab.sat.backends import available_backends, solve_cnf
from keylab.sat.cnf import CNF


def test_concrete_word_operations_fold_without_allocating_cnf_structure() -> None:
    cnf = CNF()
    value = 0x12345678
    word = BitVec32.from_int(cnf, value)

    assert word.rotr(7).extract_word() == ((value >> 7) | (value << 25)) & 0xFFFFFFFF
    assert word.xor(BitVec32.from_int(cnf, 0xFF00FF00)).extract_word() == (value ^ 0xFF00FF00)
    assert word.and_(BitVec32.from_int(cnf, 0xFFFF0000)).extract_word() == (value & 0xFFFF0000)
    assert word.or_(BitVec32.from_int(cnf, 0x0000FFFF)).extract_word() == (value | 0x0000FFFF)
    assert BitVec32.from_int(cnf, 0xFFFFFFFF).add(BitVec32.from_int(cnf, 1)).extract_word() == 0
    assert word.sigma0().extract_word() == (
        ((value >> 7) | (value << 25))
        ^ ((value >> 18) | (value << 14))
        ^ (value >> 3)
    ) & 0xFFFFFFFF
    assert cnf.variable_count == 0
    assert cnf.clauses == []


def test_bitvec_symbolic_roundtrip() -> None:
    if not available_backends():
        import pytest

        pytest.skip("no in-process SAT backend installed")
    cnf = CNF()
    secret_word = 0xFFFFFFFE
    symbolic = BitVec32.symbolic(cnf, "input")
    mask = 0x80000001
    masked = symbolic.xor(BitVec32.from_int(cnf, mask))
    rotated = masked.rotr(7)
    assert cnf.variable_count == 32
    assert cnf.clauses == []
    output = masked.add(BitVec32.from_int(cnf, 5))
    expected = ((secret_word ^ mask) + 5) & 0xFFFFFFFF
    for index, literal in enumerate(output.to_literals()):
        cnf.add_clause(literal if (expected >> index) & 1 else -literal)

    result = solve_cnf(cnf.clauses)
    assert result.status == "SATISFIABLE"
    from keylab.sat.cryptominisat import literal_value

    one_based_model = [False] * (cnf.variable_count + 1)
    for variable, value in result.assignments.items():
        one_based_model[variable] = value
    least_significant_bit = symbolic.to_literals()[0]
    assert literal_value(one_based_model, least_significant_bit) is bool(secret_word & 1)
    assert literal_value(one_based_model, -least_significant_bit) is not bool(secret_word & 1)
    assert symbolic.extract_word(result.assignments) == secret_word
    assert masked.extract_word(result.assignments) == (secret_word ^ mask)
    assert rotated.extract_word(result.assignments) == (
        (((secret_word ^ mask) >> 7) | ((secret_word ^ mask) << 25)) & 0xFFFFFFFF
    )
    assert output.extract_word(result.assignments) == expected


def test_symbolic_word_rejects_missing_model() -> None:
    word = BitVec32.symbolic(CNF(), "input")
    try:
        word.extract_word()
    except ValueError as exc:
        assert "model is required" in str(exc)
    else:
        raise AssertionError("symbolic extraction should require a model")
