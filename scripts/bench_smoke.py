"""Run the signature benchmark once in pure Python and check its report.

Usage: ``python scripts/bench_smoke.py``

CI runs this in an environment without native ECC backends, the only place
KeyLab's own arithmetic is exercised end to end by the benchmark. The
benchmark's correctness gate aborts on any wrong result; this script also
requires that no native backend was used. Timings are printed, never judged.
"""

from __future__ import annotations

import json
import sys
from importlib.util import find_spec

from keylab.benchmarks import SIGNATURE_OPERATIONS, benchmark_signatures


def main() -> int:
    native = [name for name in ("coincurve", "fastecdsa") if find_spec(name) is not None]
    if native:
        print(f"FAIL: native backends are installed ({', '.join(native)}); "
              "this check must run in pure Python")
        return 1
    report = benchmark_signatures(count=2, repetitions=1, backend="keylab")
    operations = [row["operation"] for row in report["operations"]]
    print(json.dumps({"keylab_multiplication": report["keylab_multiplication"],
                      "us_per_op": {row["operation"]: round(row["median_us_per_op"], 1)
                                    for row in report["operations"]}}, indent=2))
    if "pure Python" not in str(report["keylab_multiplication"]):
        print("FAIL: the benchmark did not use pure-Python multiplication")
        return 1
    missing = sorted(set(SIGNATURE_OPERATIONS) - set(operations))
    if missing:
        print(f"FAIL: operations missing from the report: {missing}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
