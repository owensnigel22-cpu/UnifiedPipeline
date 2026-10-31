"""Micro-benchmarks of KeyLab's curve primitives and signature paths.

Usage: ``python scripts/bench_micro.py > report.json``

Times field and point primitives, each scalar-multiplication strategy, and the
public verify/sign/tweak paths on a seeded public corpus, reporting the median
of five repetitions in microseconds. With no native backend installed every
row is pure Python; with coincurve installed, ``backend="auto"`` paths (verify,
sign, tweak) use libsecp256k1 for their multiplications, which the report's
``native_backends_importable`` field records. Used for the v0.2.0 baseline in
docs/performance_baseline_v0.2.0.md and for later comparisons.
"""

from __future__ import annotations

import json
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable
from importlib.util import find_spec

from keylab import __version__
from keylab.ec import secp256k1 as curve
from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.encoding.taproot import taproot_output

SEED = 20261031
REPETITIONS = 5


def _median_us(operation: Callable[[int], object], iterations: int) -> float:
    samples = []
    for _ in range(REPETITIONS):
        start = time.perf_counter()
        for index in range(iterations):
            operation(index)
        samples.append((time.perf_counter() - start) / iterations * 1e6)
    return round(statistics.median(samples), 2)


def run() -> dict[str, object]:
    rng = random.Random(SEED)
    scalars = [rng.randrange(1, curve.N) for _ in range(64)]
    digests = [rng.randbytes(32) for _ in range(64)]
    point = curve.scalar_mult(scalars[0], curve.G, backend="python")
    jacobian = curve._to_jacobian(point)
    doubled = curve.point_double(jacobian)
    ecdsa = [
        (digest, curve.ecdsa_sign_digest(digest, key, backend="python"),
         curve.scalar_mult(key, curve.G, backend="python"))
        for digest, key in zip(digests[:16], scalars[:16], strict=True)
    ]
    schnorr = [
        (digest, schnorr_sign(digest, key, bytes(32)), schnorr_public_key(key))
        for digest, key in zip(digests[:16], scalars[:16], strict=True)
    ]

    def scalar(index: int) -> int:
        return scalars[index % 64]

    results = {
        "jacobian_double_us": _median_us(lambda i: curve.point_double(doubled), 5000),
        "jacobian_add_us": _median_us(lambda i: curve.point_add(doubled, jacobian), 5000),
        "mixed_add_us": _median_us(lambda i: curve._point_add_mixed(doubled, curve.G), 5000),
        "field_inverse_us": _median_us(lambda i: pow(doubled[0] + i, -1, curve.P), 5000),
        "sqrt_mod_p_us": _median_us(lambda i: curve.sqrt_mod_p(doubled[0] + i), 300),
        "kG_python_us": _median_us(
            lambda i: curve.scalar_mult(scalar(i), curve.G, backend="python"), 16),
        "kG_wnaf_us": _median_us(
            lambda i: curve.scalar_mult(scalar(i), curve.G, backend="python-wnaf"), 16),
        "kG_affine_window_us": _median_us(
            lambda i: curve.scalar_mult(scalar(i), curve.G, backend="python-affine-window"), 16),
        "kP_python_us": _median_us(
            lambda i: curve.scalar_mult(scalar(i), point, backend="python"), 16),
        "kP_glv_us": _median_us(
            lambda i: curve.scalar_mult(scalar(i), point, backend="python-glv"), 16),
        "ecdsa_verify_us": _median_us(lambda i: curve.ecdsa_verify_digest(*ecdsa[i % 16]), 16),
        "schnorr_verify_us": _median_us(lambda i: schnorr_verify(*schnorr[i % 16]), 16),
        "schnorr_sign_us": _median_us(
            lambda i: schnorr_sign(digests[i % 64], scalar(i), bytes(32)), 16),
        "taproot_output_us": _median_us(
            lambda i: taproot_output(schnorr[i % 16][2], digests[i % 64]), 16),
    }
    return {
        "keylab_version": __version__,
        "seed": SEED,
        "repetitions": REPETITIONS,
        "statistic": "median",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "native_backends_importable": [
            name for name in ("coincurve", "fastecdsa") if find_spec(name) is not None
        ],
        "results_us": results,
    }


def main() -> int:
    json.dump(run(), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
