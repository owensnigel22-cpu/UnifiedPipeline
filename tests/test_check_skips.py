"""scripts/check_skips.py: only explicitly allowed skip reasons pass."""

from __future__ import annotations

from scripts import check_skips

PASSED = '<testcase classname="t" name="ok" time="0"/>'
SAT_SKIP = ('<testcase classname="t" name="sat" time="0"><skipped type="pytest.skip" '
            'message="no supported external SAT solver is installed">x</skipped></testcase>')
ECC_SKIP = ('<testcase classname="t" name="ecc" time="0"><skipped type="pytest.skip" '
            "message=\"could not import 'fastecdsa'\">x</skipped></testcase>")
FAILURE = '<testcase classname="t" name="bad" time="0"><failure message="boom">x</failure></testcase>'


def _report(tmp_path, *cases: str):
    path = tmp_path / "junit.xml"
    path.write_text(f'<testsuites><testsuite name="pytest">{"".join(cases)}</testsuite></testsuites>',
                    encoding="utf-8")
    return path


def test_a_run_without_skips_passes(tmp_path) -> None:
    assert check_skips.main([str(_report(tmp_path, PASSED, PASSED))]) == 0


def test_an_allowed_skip_passes(tmp_path) -> None:
    path = _report(tmp_path, PASSED, SAT_SKIP)
    assert check_skips.main([str(path), "--allow", "external SAT solver"]) == 0


def test_any_skip_fails_without_an_allowlist(tmp_path, capsys) -> None:
    assert check_skips.main([str(_report(tmp_path, PASSED, ECC_SKIP))]) == 1
    assert "UNEXPECTED" in capsys.readouterr().out


def test_a_skip_outside_the_allowlist_fails(tmp_path) -> None:
    path = _report(tmp_path, SAT_SKIP, ECC_SKIP)
    report = check_skips.analyse(path, ["external SAT solver"])
    assert sum(report.allowed.values()) == 1
    assert list(report.unexpected) == ["could not import 'fastecdsa'"]
    assert check_skips.main([str(path), "--allow", "external SAT solver"]) == 1


def test_failures_and_empty_reports_fail(tmp_path) -> None:
    assert check_skips.main([str(_report(tmp_path, PASSED, FAILURE))]) == 1
    assert check_skips.main([str(_report(tmp_path))]) == 1
