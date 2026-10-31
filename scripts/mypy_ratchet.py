"""Fail when the mypy error count differs from the recorded baseline.

Usage: ``python scripts/mypy_ratchet.py [--baseline PATH]``

mypy runs with the project's ``[tool.mypy]`` configuration. More errors than the
baseline fails (new type errors); fewer also fails, with a request to lower the
baseline, so every fix is locked in by the change that makes it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_BASELINE = Path(__file__).with_name("mypy_baseline.txt")
_SUMMARY = re.compile(r"^Found (\d+) errors? in \d+ files?")


def read_baseline(path: Path) -> int:
    """Return the integer on the first non-comment, non-blank line of ``path``."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return int(stripped)
    raise ValueError(f"{path} contains no baseline count")


def count_errors(output: str) -> int:
    """Return the error count from mypy's summary line (0 for "Success")."""
    for line in reversed(output.splitlines()):
        if line.startswith("Success: no issues found"):
            return 0
        match = _SUMMARY.match(line)
        if match:
            return int(match.group(1))
    raise ValueError("mypy output has no summary line:\n" + output[-2000:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    args = parser.parse_args(argv)

    baseline = read_baseline(args.baseline)
    result = subprocess.run(
        [sys.executable, "-m", "mypy"], capture_output=True, text=True, check=False
    )
    output = result.stdout + result.stderr
    if result.returncode not in (0, 1):
        print(output)
        print(f"mypy failed to run (exit {result.returncode})")
        return 2
    errors = count_errors(output)
    print(f"mypy errors: {errors} (baseline {baseline})")
    if errors > baseline:
        print(output)
        print(f"FAIL: {errors - baseline} new mypy error(s); fix them before merging.")
        return 1
    if errors < baseline:
        print(f"FAIL: mypy errors fell to {errors}; lower {args.baseline.name} to {errors}.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
