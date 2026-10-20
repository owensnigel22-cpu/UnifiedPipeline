from keylab.feature_audit import feature_audit


def test_feature_audit_reports_source_evidence_without_claiming_test_execution() -> None:
    report = feature_audit()
    assert report
    assert all(row["implementation_present"] for row in report)
    assert all("not persisted" in row["benchmark_record"] for row in report)
    assert any(row["feature"] == "Walkback SHA-256 state trace" for row in report)


def test_feature_audit_cli_emits_json(capsys) -> None:
    from keylab.cli import main

    assert main(["feature-audit"]) == 0
    assert '"audit"' in capsys.readouterr().out


def test_symbolic_sha_cli_solves_and_forward_verifies(capsys) -> None:
    from keylab.sat.backends import available_backends

    if not available_backends():
        import pytest

        pytest.skip("no in-process SAT backend installed")
    from keylab.cli import main

    assert main(["sha256-symbolic-roundtrip", "--message", "534154", "--rounds", "2"]) == 0
    output = capsys.readouterr().out
    assert '"target_verified": true' in output
    assert '"matches_fixture": true' in output


def test_symbolic_sha_roundtrip_recovers_input_and_signed_literals() -> None:
    from keylab.hashes.reduced import sha256_reduced
    from keylab.hashes.sha256_cnf import sha256_hash_preimage_cnf
    from keylab.sat.backends import available_backends, solve_cnf
    from keylab.sat.cryptominisat import literal_value

    if not available_backends():
        import pytest

        pytest.skip("no in-process SAT backend installed")
    message = b"SAT"
    model = sha256_hash_preimage_cnf(sha256_reduced(message, rounds=2), message_length=len(message), rounds=2)
    result = solve_cnf(model.formula.clauses)
    assert result.status == "SATISFIABLE"
    assert model.recover_input(result.assignments) == message

    one_based_model = [False] * (model.variable_count + 1)
    for variable, value in result.assignments.items():
        one_based_model[variable] = value
    for variable in model.input_bits:
        value = literal_value(one_based_model, variable)
        assert literal_value(one_based_model, -variable) is (not value)
