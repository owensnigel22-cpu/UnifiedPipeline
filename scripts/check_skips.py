"""Fail CI when pytest skipped a test for a reason that is not explicitly allowed.

Usage: ``python scripts/check_skips.py JUNIT_XML [--allow TEXT ...]``

Reads pytest's ``--junitxml`` report. Every skipped test's reason must contain
one of the ``--allow`` strings; with no ``--allow``, any skip fails. The check
also fails on test failures or errors, and on a report with no tests, so a run
that silently collected nothing cannot pass.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree


@dataclass
class SkipReport:
    tests: int = 0
    failures: int = 0
    errors: int = 0
    allowed: Counter[str] = field(default_factory=Counter)
    unexpected: Counter[str] = field(default_factory=Counter)

    @property
    def ok(self) -> bool:
        return self.tests > 0 and not (self.failures or self.errors or self.unexpected)


def analyse(junit_xml: Path, allowed_reasons: list[str]) -> SkipReport:
    """Classify every skipped test in a pytest JUnit XML report."""
    report = SkipReport()
    for case in ElementTree.parse(junit_xml).getroot().iter("testcase"):
        report.tests += 1
        report.failures += len(case.findall("failure"))
        report.errors += len(case.findall("error"))
        for skipped in case.findall("skipped"):
            reason = skipped.get("message") or (skipped.text or "").strip() or "(no reason)"
            bucket = report.allowed if any(a in reason for a in allowed_reasons) else report.unexpected
            bucket[reason] += 1
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("junit_xml", type=Path)
    parser.add_argument("--allow", action="append", default=[], metavar="TEXT",
                        help="a skip reason containing TEXT is permitted (repeatable)")
    args = parser.parse_args(argv)

    report = analyse(args.junit_xml, args.allow)
    skipped = sum(report.allowed.values()) + sum(report.unexpected.values())
    print(f"tests: {report.tests}  skipped: {skipped}  failures: {report.failures}  "
          f"errors: {report.errors}")
    for reason, count in sorted(report.allowed.items()):
        print(f"  allowed    {count:3}  {reason}")
    for reason, count in sorted(report.unexpected.items()):
        print(f"  UNEXPECTED {count:3}  {reason}")
    if report.tests == 0:
        print("FAIL: the report contains no tests")
    elif report.unexpected:
        print("FAIL: tests were skipped for reasons that are not allowed in this job")
    elif report.failures or report.errors:
        print("FAIL: the report contains failures or errors")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
