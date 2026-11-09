"""Reproducible pure-Python versus Coincurve secp256k1 microbenchmark.

Run with ``PYTHONPATH=src python scripts/benchmark_ecc.py``. Fixed inputs are
created and correctness-checked before timing. Preparation is excluded; the
timed call includes the selected public wrapper/backend dispatch. No secret
material or shared-secret bytes are printed.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import statistics
import sys
import time
from collections.abc import Callable
from importlib.util import find_spec

from keylab import __version__
from keylab.ec import ecdh_coincurve, ecdh_reference
from keylab.ec.coincurve_backend import (
    ecdsa_sign_digest_coincurve,
    ecdsa_sign_digest_python,
    ecdsa_verify_digest_coincurve,
)
from keylab.ec.secp256k1 import (
    G,
    N,
    ecdsa_verify_digest,
    mod_inverse_builtin,
    multi_scalar_mult,
    public_key_from_private_scalar,
)


def _verify_python(digest: bytes, signature: tuple[int, int], public: tuple[int, int]) -> bool:
    """Run KeyLab's ECDSA equation with an explicitly pure-Python MSM backend."""
    r, s = signature
    if not 1 <= r < N or not 1 <= s < N:
        return False
    inv_s = mod_inverse_builtin(s, N)
    z = int.from_bytes(digest, "big")
    result = multi_scalar_mult(
        (((z * inv_s) % N, G), ((r * inv_s) % N, public)),
        backend="python-optimized",
    )
    return result is not None and result[0] % N == r


def _measure(
    name: str,
    operation: Callable[[int], object],
    count: int,
    repetitions: int,
) -> dict[str, object]:
    warmups = min(2, count)
    for index in range(warmups):
        operation(index)
    samples: list[float] = []
    for _ in range(repetitions):
        start = time.perf_counter()
        for index in range(count):
            operation(index)
        elapsed = time.perf_counter() - start
        samples.append(elapsed)
    rates = [count / sample for sample in samples]
    return {
        "name": name,
        "count_per_sample": count,
        "samples": repetitions,
        "median_ops_per_second": round(statistics.median(rates), 3),
        "minimum_ops_per_second": round(min(rates), 3),
        "maximum_ops_per_second": round(max(rates), 3),
        "median_seconds_per_sample": round(statistics.median(samples), 6),
        "warmup_operations_excluded": warmups,
        "preparation_included": False,
    }


def run(count: int, repetitions: int) -> dict[str, object]:
    privates = [int.from_bytes(hashlib.sha256(f"keylab-m10-key-{i}".encode()).digest(), "big") % (N - 1) + 1
                for i in range(count)]
    peer_scalars = [int.from_bytes(hashlib.sha256(f"keylab-m10-peer-{i}".encode()).digest(), "big") % (N - 1) + 1
                    for i in range(count)]
    digests = [hashlib.sha256(f"keylab-m10-digest-{i}".encode()).digest() for i in range(count)]
    public_keys = [public_key_from_private_scalar(key, backend="python-optimized") for key in privates]
    peer_points = [public_key_from_private_scalar(key, backend="python-optimized") for key in peer_scalars]

    python_signatures = [
        ecdsa_sign_digest_python(digest, private)
        for digest, private in zip(digests, privates, strict=True)
    ]
    if not all(
        _verify_python(digest, signature, public)
        for digest, signature, public in zip(digests, python_signatures, public_keys, strict=True)
    ):
        raise RuntimeError("pure-Python ECDSA preflight failed")
    if not all(
        ecdh_reference(private, peer) == ecdh_reference(peer_scalar, public)
        for private, peer, peer_scalar, public in zip(
            privates, peer_points, peer_scalars, public_keys, strict=True
        )
    ):
        raise RuntimeError("pure-Python ECDH preflight failed")

    measurements = [
        _measure("ECDH pure Python", lambda i: ecdh_reference(privates[i], peer_points[i]), count, repetitions),
        _measure("ECDSA sign pure Python", lambda i: ecdsa_sign_digest_python(digests[i], privates[i]), count, repetitions),
        _measure("ECDSA verify pure Python", lambda i: _verify_python(digests[i], python_signatures[i], public_keys[i]), count, repetitions),
    ]

    coincurve_available = find_spec("coincurve") is not None
    native_version = None
    if coincurve_available:
        import coincurve

        native_version = getattr(coincurve, "__version__", "unknown")
        native_signatures = [
            ecdsa_sign_digest_coincurve(digest, private)
            for digest, private in zip(digests, privates, strict=True)
        ]
        if not all(
            signature == native
            and ecdsa_verify_digest(digest, native, public)
            and ecdsa_verify_digest_coincurve(digest, signature, public)
            for digest, signature, native, public in zip(
                digests, python_signatures, native_signatures, public_keys, strict=True
            )
        ):
            raise RuntimeError("Coincurve ECDSA differential preflight failed")
        if not all(
            ecdh_coincurve(private, peer) == ecdh_reference(private, peer)
            for private, peer in zip(privates, peer_points, strict=True)
        ):
            raise RuntimeError("Coincurve ECDH differential preflight failed")
        measurements.extend([
            _measure("ECDH Coincurve", lambda i: ecdh_coincurve(privates[i], peer_points[i]), count, repetitions),
            _measure("ECDSA sign Coincurve", lambda i: ecdsa_sign_digest_coincurve(digests[i], privates[i]), count, repetitions),
            _measure("ECDSA verify Coincurve", lambda i: ecdsa_verify_digest_coincurve(digests[i], native_signatures[i], public_keys[i]), count, repetitions),
        ])

    for row in measurements:
        name = str(row["name"])
        if " pure Python" in name:
            native_name = name.replace(" pure Python", " Coincurve")
            native = next((item for item in measurements if item["name"] == native_name), None)
            row["coincurve_comparison"] = (
                None if native is None else round(
                    float(native["median_ops_per_second"]) / float(row["median_ops_per_second"]), 3
                )
            )

    return {
        "project_version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
        "coincurve_available": coincurve_available,
        "coincurve_version": native_version,
        "input_count": count,
        "repetitions": repetitions,
        "corpus": "deterministic SHA-256-derived secp256k1 keys and digests",
        "timing_notes": (
            "Corpus construction, key derivation, signatures, validation preflight, and correctness checks are excluded. "
            "Each timed call includes the selected API's dispatch and operation. Warm-up operations are excluded."
        ),
        "measurements": measurements,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8, help="operations per timing sample (default: 8)")
    parser.add_argument("--repetitions", type=int, default=5, help="timing samples (default: 5)")
    args = parser.parse_args()
    if args.count < 1 or args.repetitions < 2:
        parser.error("--count must be positive and --repetitions must be at least 2")
    result = run(args.count, args.repetitions)
    print(f"Python: {result['python'].splitlines()[0]}")
    print(f"Platform: {result['platform']}")
    print(f"Coincurve: {result['coincurve_version'] or 'unavailable'}")
    print(f"Corpus count/sample: {args.count}; repetitions: {args.repetitions}")
    for row in result["measurements"]:
        speedup = row.get("coincurve_comparison")
        speedup_text = "n/a" if speedup is None else f"{speedup}x"
        print(
            f"{row['name']}: median={row['median_ops_per_second']} ops/s "
            f"(min={row['minimum_ops_per_second']}, max={row['maximum_ops_per_second']}); "
            f"Coincurve speedup={speedup_text}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
