"""Reproducible standalone MSM and BIP-340 batch-verification benchmark.

Run ``python scripts/benchmark_msm_schnorr_batch.py --json-output report.json``.
Correctness is checked before timing; the script never prints key material.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from importlib.metadata import PackageNotFoundError, version
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from keylab import __version__ as keylab_version
from keylab.ec import reference
from keylab.ec import secp256k1 as curve
from keylab.ec.schnorr import (
    _batch_coefficients,
    _challenge,
    _lift_x_even,
    _parse_batch_item,
    schnorr_public_key,
    schnorr_sign,
    schnorr_verify,
    schnorr_verify_batch,
)
from keylab.ec.secp256k1 import (
    G,
    N,
    Point,
    multi_scalar_mult,
    point_add_affine,
)

DEFAULT_SIZES = (1, 2, 4, 8, 16, 32, 64, 128, 256)
MSM_DISTRIBUTIONS = (
    "random",
    "small",
    "near-n",
    "zero-heavy",
    "repeated-points",
    "mixed-points",
)
SCHNORR_SCENARIOS = (
    "valid-distinct",
    "valid-repeated-key",
    "invalid-first",
    "invalid-middle",
    "invalid-last",
    "malformed-middle",
)
MESSAGE_LENGTHS = (0, 1, 32, 100)


def _middle_position(size: int) -> tuple[int, str]:
    """Return a zero-based middle index and a descriptive fixture label."""
    if size < 1:
        raise ValueError("size must be positive")
    if size == 1:
        return 0, "only"
    if size == 2:
        return 1, "middle"
    return size // 2, "middle"


def _package_version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def _validate_sizes(sizes: Sequence[int]) -> None:
    if not sizes or any(type(size) is not int or size < 1 or size > 256 for size in sizes):
        raise ValueError("sizes must be nonempty integers in [1, 256]")


def _timings(
    operation: Callable[[], object],
    *,
    repetitions: int,
    iterations: int,
) -> dict[str, float | int]:
    operation()
    samples: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for _ in range(iterations):
            operation()
        samples.append((time.perf_counter_ns() - started) / iterations)
    median_ns = statistics.median(samples)
    mean_ns = statistics.mean(samples)
    return {
        "repetitions": repetitions,
        "iterations_per_repetition": iterations,
        "warmup_operations": 1,
        "median_ns": median_ns,
        "mean_ns": mean_ns,
        "stdev_ns": statistics.stdev(samples),
        "minimum_ns": min(samples),
        "maximum_ns": max(samples),
        "operations_per_second": 1_000_000_000 / median_ns,
    }


def build_msm_corpora(
    seed: int,
    max_size: int = 128,
) -> dict[str, list[tuple[list[tuple[int, Point]], list[int]]]]:
    """Build deterministic ``(pairs, point discrete-log factors)`` prefixes.

    The point factors are retained only for an independent affine-reference
    expected result: sum(k_i * (q_i*G)) = (sum(k_i*q_i) mod N)*G.
    """
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(max_size) is not int or not 1 <= max_size <= 256:
        raise ValueError("max_size must be in [1, 256]")

    corpora: dict[str, list[tuple[list[tuple[int, Point]], list[int]]]] = {}
    for distribution_index, distribution in enumerate(MSM_DISTRIBUTIONS):
        rng = random.Random(seed + distribution_index * 1009)
        point_factors = [rng.randrange(1, N) for _ in range(max_size)]
        if distribution == "repeated-points":
            point_factors = [point_factors[0]] * max_size
        elif distribution == "mixed-points":
            fixed = (1, N - 1, 2, point_factors[0], 0)
            point_factors = [fixed[index % len(fixed)] for index in range(max_size)]

        if distribution == "small":
            scalars = [rng.randrange(0, 1 << 16) for _ in range(max_size)]
        elif distribution == "near-n":
            scalars = [N - 1 - rng.randrange(0, 1 << 16) for _ in range(max_size)]
        elif distribution == "zero-heavy":
            scalars = [0 if index % 2 == 0 else rng.randrange(1, N) for index in range(max_size)]
        else:
            scalars = [rng.randrange(0, N) for _ in range(max_size)]

        points = [reference.scalar_mult(factor, G) for factor in point_factors]
        pairs = list(zip(scalars, points, strict=True))
        corpora[distribution] = [(pairs[:size], point_factors[:size]) for size in range(1, max_size + 1)]
    return corpora


def _msm_expected(pairs: Sequence[tuple[int, Point]], point_factors: Sequence[int]) -> Point:
    total_scalar = sum(scalar * factor for (scalar, _), factor in zip(pairs, point_factors, strict=True))
    return reference.scalar_mult(total_scalar % N, G)


def _naive_glv(pairs: Sequence[tuple[int, Point]]) -> Point:
    total: Point = None
    for scalar, point in pairs:
        total = point_add_affine(
            total,
            curve.scalar_mult(scalar, point, backend="python-glv"),
        )
    return total


def _msm_methods(
    pairs: Sequence[tuple[int, Point]],
    native_backends: Sequence[str],
) -> dict[str, Callable[[], Point]]:
    methods: dict[str, Callable[[], Point]] = {
        "naive-python": lambda: multi_scalar_mult(
            pairs, method="naive", backend="python-optimized"
        ),
        "naive-python-glv": lambda: _naive_glv(pairs),
        "straus-glv-wnaf": lambda: multi_scalar_mult(pairs, method="straus"),
        "pippenger-python": lambda: multi_scalar_mult(pairs, method="pippenger"),
        "auto-python": lambda: multi_scalar_mult(
            pairs, method="auto", backend="python-optimized"
        ),
    }
    for backend in native_backends:
        methods[f"naive-{backend}"] = (
            lambda selected=backend: multi_scalar_mult(
                pairs, method="naive", backend=selected
            )
        )
    return methods


def benchmark_msm(
    *,
    seed: int = 20261122,
    sizes: Sequence[int] = DEFAULT_SIZES,
    distributions: Sequence[str] = MSM_DISTRIBUTIONS,
    repetitions: int = 5,
    iterations: int = 1,
) -> list[dict[str, Any]]:
    _validate_sizes(sizes)
    if any(name not in MSM_DISTRIBUTIONS for name in distributions) or not distributions:
        raise ValueError(f"distributions must be selected from {MSM_DISTRIBUTIONS}")
    if repetitions < 2 or iterations < 1:
        raise ValueError("repetitions must be at least 2 and iterations positive")
    corpora = build_msm_corpora(seed, max(sizes))
    native_backends = [
        backend for backend in ("coincurve", "fastecdsa")
        if find_spec(backend) is not None
    ]
    rows: list[dict[str, Any]] = []
    for distribution in distributions:
        for size in sizes:
            pairs, factors = corpora[distribution][size - 1]
            expected = _msm_expected(pairs, factors)
            methods = _msm_methods(pairs, native_backends)
            baseline_ns: float | None = None
            glv_baseline_ns: float | None = None
            for name, operation in methods.items():
                actual = operation()
                if actual != expected:
                    raise ArithmeticError(
                        f"MSM correctness preflight failed: {distribution=} {size=} {name=}"
                    )
                measured = _timings(
                    operation, repetitions=repetitions, iterations=iterations
                )
                if name == "naive-python":
                    baseline_ns = float(measured["median_ns"])
                if name == "naive-python-glv":
                    glv_baseline_ns = float(measured["median_ns"])
                measured.update(
                    {
                        "benchmark": "msm",
                        "distribution": distribution,
                        "batch_size": size,
                        "method": name,
                        "correctness": "matched independent affine reference",
                        "time_per_pair_ns": float(measured["median_ns"]) / size,
                        "pairs_per_second": size * 1_000_000_000 / float(measured["median_ns"]),
                    }
                )
                rows.append(measured)
            for row in rows:
                if (
                    row.get("benchmark") == "msm"
                    and row.get("distribution") == distribution
                    and row.get("batch_size") == size
                ):
                    row["speedup_vs_naive_python"] = (
                        None if baseline_ns is None
                        else baseline_ns / float(row["median_ns"])
                    )
                    row["speedup_vs_naive_python_glv"] = (
                        None if glv_baseline_ns is None
                        else glv_baseline_ns / float(row["median_ns"])
                    )
    return rows


def _messages(seed: int, count: int) -> list[bytes]:
    rng = random.Random(seed)
    return [
        rng.randbytes(MESSAGE_LENGTHS[index % len(MESSAGE_LENGTHS)])
        for index in range(count)
    ]


def build_schnorr_items(
    seed: int,
    count: int,
    *,
    repeated_key: bool = False,
) -> list[tuple[bytes, bytes, bytes]]:
    """Create reproducible valid signatures with fixed auxiliary randomness."""
    if type(seed) is not int or seed < 0 or type(count) is not int or count < 1:
        raise ValueError("seed must be nonnegative and count positive")
    rng = random.Random(seed)
    repeated_private = rng.randrange(1, N)
    items = []
    for index, message in enumerate(_messages(seed ^ 0x5343484E, count)):
        private = repeated_private if repeated_key else rng.randrange(1, N)
        aux_rand = hashlib.sha256(f"{seed}:aux:{index}".encode()).digest()
        items.append(
            (message, schnorr_sign(message, private, aux_rand), schnorr_public_key(private))
        )
    return items


def _corrupt_signature(item: tuple[bytes, bytes, bytes]) -> tuple[bytes, bytes, bytes]:
    message, signature, public_key = item
    r = signature[:32]
    s = (int.from_bytes(signature[32:], "big") + 1) % N
    corrupted = (message, r + s.to_bytes(32, "big"), public_key)
    if schnorr_verify(*corrupted):
        raise ArithmeticError("deterministic signature mutation unexpectedly verified")
    return corrupted


def _scenario_items(
    seed: int,
    size: int,
    scenario: str,
) -> tuple[list[tuple[bytes, bytes, bytes]], int | None, str | None]:
    if type(size) is not int or size < 1:
        raise ValueError("size must be positive")
    repeated = scenario == "valid-repeated-key"
    items = build_schnorr_items(seed + size * 37, size, repeated_key=repeated)
    invalid_position: int | None = None
    invalid_position_label: str | None = None
    if scenario.startswith("invalid-"):
        suffix = scenario.removeprefix("invalid-")
        if suffix == "first":
            invalid_position = 0
            invalid_position_label = "first"
        elif suffix == "middle":
            invalid_position, invalid_position_label = _middle_position(size)
        elif suffix == "last":
            invalid_position = size - 1
            invalid_position_label = "last"
        else:
            raise ValueError(f"unknown invalid Schnorr scenario: {scenario}")
        items[invalid_position] = _corrupt_signature(items[invalid_position])
    elif scenario == "malformed-middle":
        invalid_position, invalid_position_label = _middle_position(size)
        message, signature, public_key = items[invalid_position]
        items[invalid_position] = (message, signature[:-1], public_key)
    elif scenario not in ("valid-distinct", "valid-repeated-key"):
        raise ValueError(f"unknown Schnorr scenario: {scenario}")
    return items, invalid_position, invalid_position_label


def _individual_results(items: Sequence[tuple[bytes, bytes, bytes]]) -> list[bool]:
    return [schnorr_verify(message, signature, public_key) for message, signature, public_key in items]


def _deterministic_coefficients(seed: int, count: int) -> list[int]:
    coefficients = [1]
    for index in range(1, count):
        material = f"{seed}:coefficient:{index}".encode()
        coefficients.append(int.from_bytes(hashlib.sha256(material).digest(), "big") % (N - 1) + 1)
    return coefficients


def _native_schnorr_preflight(
    items: Sequence[tuple[bytes, bytes, bytes]],
) -> dict[str, Any]:
    if find_spec("coincurve") is None:
        return {"available": False, "result": "not installed"}
    from coincurve import PublicKeyXOnly

    checked = 0
    unsupported: dict[str, int] = {}
    for message, signature, public_key in items:
        if not isinstance(message, bytes):
            unsupported["unsupported_message_type"] = (
                unsupported.get("unsupported_message_type", 0) + 1
            )
            continue
        if len(public_key) != 32:
            unsupported["unsupported_public_key_length"] = (
                unsupported.get("unsupported_public_key_length", 0) + 1
            )
            continue
        if len(signature) != 64:
            unsupported["malformed_signature_length"] = unsupported.get(
                "malformed_signature_length", 0
            ) + 1
            continue
        try:
            native_key = PublicKeyXOnly(public_key)
        except (ValueError, TypeError) as exc:
            label = f"public_key_parser:{type(exc).__name__}"
            unsupported[label] = unsupported.get(label, 0) + 1
            continue
        try:
            native_result = native_key.verify(signature, message)
        except (ValueError, TypeError) as exc:
            label = f"signature_parser:{type(exc).__name__}"
            unsupported[label] = unsupported.get(label, 0) + 1
            continue
        local_result = schnorr_verify(message, signature, public_key)
        if native_result != local_result:
            raise ArithmeticError("Coincurve and KeyLab Schnorr verification disagree")
        checked += 1
    return {
        "available": True,
        "implementation": "Coincurve/libsecp256k1",
        "checked": checked,
        "unsupported_or_parser_rejected": unsupported,
        "interpretation": "Parser/API rejection is recorded separately, not counted as an agreement.",
    }


def _native_individual_setup(
    items: Sequence[tuple[bytes, bytes, bytes]],
) -> tuple[list[object] | None, dict[str, int]]:
    """Parse native x-only keys outside timing and classify unsupported fixtures."""
    if find_spec("coincurve") is None:
        return None, {"coincurve_not_installed": 1}
    from coincurve import PublicKeyXOnly

    keys: list[object] = []
    unsupported: dict[str, int] = {}
    for _, signature, public_key in items:
        if len(signature) != 64:
            unsupported["malformed_signature_length"] = (
                unsupported.get("malformed_signature_length", 0) + 1
            )
            continue
        if len(public_key) != 32:
            unsupported["malformed_public_key_length"] = (
                unsupported.get("malformed_public_key_length", 0) + 1
            )
            continue
        try:
            keys.append(PublicKeyXOnly(public_key))
        except (TypeError, ValueError) as exc:
            unsupported[f"public_key_parser:{type(exc).__name__}"] = (
                unsupported.get(f"public_key_parser:{type(exc).__name__}", 0) + 1
            )
    if len(keys) != len(items):
        return None, unsupported
    return keys, unsupported


def _native_individual_verify(
    items: Sequence[tuple[bytes, bytes, bytes]],
    keys: Sequence[object],
) -> bool:
    """Verify one native signature at a time; it is not a native batch API."""
    from coincurve import PublicKeyXOnly

    results = []
    for (message, signature, _), key in zip(items, keys, strict=True):
        if not isinstance(key, PublicKeyXOnly):
            return False
        try:
            results.append(bool(key.verify(signature, message)))
        except (TypeError, ValueError):
            return False
    return all(results)


def benchmark_schnorr(
    *,
    seed: int = 20261122,
    sizes: Sequence[int] = DEFAULT_SIZES,
    scenarios: Sequence[str] = SCHNORR_SCENARIOS,
    repetitions: int = 5,
    iterations: int = 1,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _validate_sizes(sizes)
    if any(name not in SCHNORR_SCENARIOS for name in scenarios) or not scenarios:
        raise ValueError(f"scenarios must be selected from {SCHNORR_SCENARIOS}")
    if repetitions < 2 or iterations < 1:
        raise ValueError("repetitions must be at least 2 and iterations positive")

    rows: list[dict[str, Any]] = []
    native_counts = {
        "available": find_spec("coincurve") is not None,
        "checked": 0,
        "unsupported": {},
        "batch_api_available": False,
        "batch_api_evidence": (
            "Coincurve/PublicKeyXOnly exposes only individual verify; "
            "no native batch API was found."
        ),
    }
    for scenario_index, scenario in enumerate(scenarios):
        for size in sizes:
            items, invalid_position, invalid_position_label = _scenario_items(
                seed + scenario_index * 10007, size, scenario
            )
            individual = _individual_results(items)
            expected = all(individual)
            if scenario.startswith("invalid-") or scenario == "malformed-middle":
                if sum(not outcome for outcome in individual) != 1:
                    raise ArithmeticError("invalid batch fixture must contain exactly one invalid item")
            elif not expected:
                raise ArithmeticError("valid batch fixture failed individual verification")

            deterministic_coefficients = _deterministic_coefficients(seed + size, size)
            deterministic_result = schnorr_verify_batch(
                items, coefficients=deterministic_coefficients
            )
            production_result = schnorr_verify_batch(items)
            if deterministic_result != expected or production_result != expected:
                raise ArithmeticError(
                    f"batch/individual correctness preflight failed: {scenario=} {size=}"
                )

            native = _native_schnorr_preflight(items)
            if native["available"]:
                native_counts["checked"] += native["checked"]
                for label, count in native["unsupported_or_parser_rejected"].items():
                    native_counts["unsupported"][label] = (
                        native_counts["unsupported"].get(label, 0) + count
                    )

            native_keys, native_setup_unsupported = _native_individual_setup(items)
            native_individual_timing = None
            if native_keys is not None:
                native_result = _native_individual_verify(items, native_keys)
                if native_result != expected:
                    raise ArithmeticError(
                        f"native/individual correctness preflight failed: {scenario=} {size=}"
                    )
                native_individual_operation = (
                    lambda current_items=items, current_keys=native_keys:
                    _native_individual_verify(current_items, current_keys)
                )
                native_individual_timing = _timings(
                    native_individual_operation,
                    repetitions=repetitions,
                    iterations=iterations,
                )
            elif native_setup_unsupported:
                for label, count in native_setup_unsupported.items():
                    native_counts["unsupported"][label] = (
                        native_counts["unsupported"].get(label, 0) + count
                    )

            individual_operation = lambda current_items=items: _individual_results(current_items)
            production_batch_operation = lambda current_items=items: schnorr_verify_batch(
                current_items
            )
            deterministic_batch_operation = (
                lambda current_items=items, coefficients=deterministic_coefficients:
                schnorr_verify_batch(current_items, coefficients=coefficients)
            )
            individual_timing = _timings(
                individual_operation, repetitions=repetitions, iterations=iterations
            )
            production_timing = _timings(
                production_batch_operation, repetitions=repetitions, iterations=iterations
            )
            deterministic_timing = _timings(
                deterministic_batch_operation, repetitions=repetitions, iterations=iterations
            )
            for mode, timing in (
                ("individual", individual_timing),
                ("batch-csprng", production_timing),
                ("batch-fixed-coefficients", deterministic_timing),
            ):
                row = dict(timing)
                row.update(
                    {
                        "benchmark": "bip340-verification",
                        "scenario": scenario,
                        "batch_size": size,
                        "invalid_position": invalid_position,
                        "invalid_position_label": invalid_position_label,
                        "mode": mode,
                        "all_items_valid": expected,
                        "individual_results": len(individual),
                        "correctness": "matched individual verification",
                    }
                )
                rows.append(row)

            if native_individual_timing is not None:
                native_row = dict(native_individual_timing)
                native_row.update(
                    {
                        "benchmark": "bip340-verification",
                        "scenario": scenario,
                        "batch_size": size,
                        "invalid_position": invalid_position,
                        "invalid_position_label": invalid_position_label,
                        "mode": "native-individual-libsecp256k1",
                        "all_items_valid": expected,
                        "individual_results": len(individual),
                        "correctness": "matched Python individual verification",
                        "public_key_setup_excluded": True,
                        "backend": "coincurve",
                        "native_batch_api_used": False,
                    }
                )
                native_row["batch_total_ns"] = None
                native_row["average_ns_per_signature"] = (
                    float(native_row["median_ns"]) / size
                )
                native_row["speedup_vs_individual_total"] = (
                    float(individual_timing["median_ns"])
                    / float(native_row["median_ns"])
                )
                native_row["batch_one_note"] = (
                    "Native individual verification measured as one call per signature."
                )
                native_row["invalid_batch_time_ratio_vs_valid"] = None
                rows.append(native_row)

            speedup = float(individual_timing["median_ns"]) / float(production_timing["median_ns"])
            deterministic_speedup = float(individual_timing["median_ns"]) / float(
                deterministic_timing["median_ns"]
            )
            for row in rows[-3:]:
                row["batch_total_ns"] = (
                    row["median_ns"] if row["mode"] != "individual" else None
                )
                row["average_ns_per_signature"] = float(row["median_ns"]) / size
                row["speedup_vs_individual_total"] = (
                    1.0 if row["mode"] == "individual"
                    else speedup if row["mode"] == "batch-csprng"
                    else deterministic_speedup
                )
                row["batch_one_note"] = (
                    "Measured as-is; batch size one has no assumed speedup."
                    if size == 1 else None
                )
                row["invalid_batch_time_ratio_vs_valid"] = None

    valid_baseline: dict[int, float] = {}
    for row in rows:
        if row["scenario"] == "valid-distinct" and row["mode"] == "batch-csprng":
            valid_baseline[row["batch_size"]] = float(row["median_ns"])
    for row in rows:
        if row["mode"] == "batch-csprng" and not row["all_items_valid"]:
            valid_time = valid_baseline.get(row["batch_size"])
            if valid_time:
                row["invalid_batch_time_ratio_vs_valid"] = float(row["median_ns"]) / valid_time
    return rows, native_counts


def benchmark_verification_components(
    *,
    seed: int = 20261122,
    sizes: Sequence[int] = DEFAULT_SIZES,
    repetitions: int = 20,
    iterations: int = 1,
) -> list[dict[str, Any]]:
    """Profile batch-verification components outside fixture construction."""
    _validate_sizes(sizes)
    if repetitions < 2 or iterations < 1:
        raise ValueError("repetitions must be at least 2 and iterations positive")

    rows: list[dict[str, Any]] = []
    for size in sizes:
        items = build_schnorr_items(seed + size * 37, size)
        parsed = [_parse_batch_item(item) for item in items]
        if any(entry is None for entry in parsed):
            raise ArithmeticError("component fixture did not parse")

        def coefficient_generation(*, count: int = size) -> list[int]:
            return _batch_coefficients(count)

        def signature_parsing(*, fixture: object = items) -> list[tuple[int, int]]:
            return [
                (
                    int.from_bytes(signature[:32], "big"),
                    int.from_bytes(signature[32:], "big"),
                )
                for _, signature, _ in fixture
            ]

        def public_key_parsing(*, fixture: object = items) -> list[Point]:
            points = []
            for public_key in (item[2] for item in fixture):
                point = _lift_x_even(int.from_bytes(public_key, "big"))
                if point is None:
                    raise ArithmeticError("fixture public key did not lift")
                points.append(point)
            return points

        def challenge_computation(*, fixture: object = items) -> list[int]:
            return [
                _challenge(signature[:32], public_key, message)
                for message, signature, public_key in fixture
            ]

        def full_parse(*, fixture: object = items) -> list[object]:
            return [_parse_batch_item(item) for item in fixture]

        def scalar_aggregation(
            *,
            count: int = size,
            entries: object = parsed,
        ) -> tuple[int, list[tuple[int, Point]]]:
            coefficients = _batch_coefficients(count)
            left_scalar = 0
            terms: list[tuple[int, Point]] = []
            for entry, coefficient in zip(entries, coefficients, strict=True):
                if entry is None:
                    raise ArithmeticError("fixture entry unexpectedly invalid")
                nonce_point, public_point, s, e = entry
                left_scalar = (left_scalar + coefficient * s) % N
                terms.append(((N - coefficient) % N, nonce_point))
                terms.append(((N - coefficient * e) % N, public_point))
            terms.append((left_scalar, G))
            return left_scalar, terms

        def nonce_msm(*, count: int = size, entries: object = parsed) -> Point:
            coefficients = _batch_coefficients(count)
            result_terms = []
            for entry, coefficient in zip(entries, coefficients, strict=True):
                if entry is None:
                    raise ArithmeticError("fixture entry unexpectedly invalid")
                nonce_point, _, _, _ = entry
                result_terms.append(((N - coefficient) % N, nonce_point))
            return multi_scalar_mult(result_terms, method="auto")

        def public_key_msm(*, count: int = size, entries: object = parsed) -> Point:
            coefficients = _batch_coefficients(count)
            result_terms = []
            for entry, coefficient in zip(entries, coefficients, strict=True):
                if entry is None:
                    raise ArithmeticError("fixture entry unexpectedly invalid")
                _, public_point, _, e = entry
                result_terms.append(((N - coefficient * e) % N, public_point))
            return multi_scalar_mult(result_terms, method="auto")

        def end_to_end_csprng(*, fixture: object = items) -> bool:
            return schnorr_verify_batch(fixture)

        def end_to_end_individual(*, fixture: object = items) -> bool:
            return all(schnorr_verify(*item) for item in fixture)

        def deterministic_batch(*, fixture: object = items, count: int = size) -> bool:
            coefficients = [
                1,
                *(
                    (37 * index + 11) % (N - 1) + 1
                    for index in range(1, count)
                ),
            ]
            return schnorr_verify_batch(fixture, coefficients=coefficients)

        def native_public_key_parsing(*, fixture: object = items) -> int:
            if find_spec("coincurve") is None:
                return 0
            from coincurve import PublicKeyXOnly

            keys = [PublicKeyXOnly(public_key) for _, _, public_key in fixture]
            return len(keys)

        def native_individual_verification(*, fixture: object = items) -> bool:
            if find_spec("coincurve") is None:
                return True
            native_keys, unsupported = _native_individual_setup(fixture)
            if native_keys is None:
                return bool(unsupported)
            return _native_individual_verify(fixture, native_keys)

        components: dict[str, Callable[[], object]] = {
            "coefficient-generation": coefficient_generation,
            "signature-parsing": signature_parsing,
            "public-key-parsing": public_key_parsing,
            "challenge-computation": challenge_computation,
            "full-signature-and-point-parsing": full_parse,
            "scalar-and-term-aggregation": scalar_aggregation,
            "nonce-msm": nonce_msm,
            "public-key-msm": public_key_msm,
            "individual-end-to-end": end_to_end_individual,
            "batch-csprng-end-to-end": end_to_end_csprng,
            "batch-fixed-coefficients-end-to-end": deterministic_batch,
            "native-public-key-parsing": native_public_key_parsing,
            "native-individual-verification": native_individual_verification,
        }
        for component, operation in components.items():
            if component == "individual-end-to-end":
                actual = end_to_end_individual()
            elif component == "batch-csprng-end-to-end":
                actual = end_to_end_csprng()
            elif component == "batch-fixed-coefficients-end-to-end":
                actual = deterministic_batch()
            else:
                actual = operation()
            if component.endswith("end-to-end") and actual is not True:
                raise ArithmeticError(
                    f"component fixture failed: batch_size={size} component={component}"
                )
            measured = _timings(operation, repetitions=repetitions, iterations=iterations)
            measured.update(
                {
                    "benchmark": "bip340-component-profile",
                    "batch_size": size,
                    "component": component,
                    "fixture_construction_excluded": True,
                    "instrumented": component in {
                        "signature-parsing",
                        "public-key-parsing",
                        "challenge-computation",
                        "full-signature-and-point-parsing",
                        "scalar-and-term-aggregation",
                        "nonce-msm",
                        "public-key-msm",
                    },
                    "correctness": "preflight passed",
                }
            )
            rows.append(measured)
    return rows


def _environment(
    seed: int,
    repetitions: int,
    iterations: int,
    component_repetitions: int = 20,
) -> dict[str, Any]:
    native = [name for name in ("coincurve", "fastecdsa") if find_spec(name) is not None]
    auto_scalar_backend = native[0] if native else "pure-python"
    return {
        "keylab_version": keylab_version,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "seed": seed,
        "repetitions": repetitions,
        "component_repetitions": component_repetitions,
        "iterations_per_repetition": iterations,
        "warmup_operations": 1,
        "optional_backends": {
            "coincurve": _package_version("coincurve"),
            "fastecdsa": _package_version("fastecdsa"),
        },
        "keylab_auto_scalar_backend": auto_scalar_backend,
        "timing": (
            "perf_counter_ns; each row reports median, mean, sample standard deviation, "
            "minimum and maximum per operation. Fixture setup and preflight are excluded."
        ),
        "speedup_definition": "baseline median ns / comparison median ns",
        "security_note": (
            "Timing is environment-dependent and is not constant-time or side-channel evidence."
        ),
    }


def _summary_table(report: dict[str, Any]) -> None:
    print(f"KeyLab {report['environment']['keylab_version']}; "
          f"Python {report['environment']['python'].splitlines()[0]}; "
          f"{report['environment']['platform']}")
    print(f"seed={report['environment']['seed']} repetitions={report['environment']['repetitions']} "
          f"iterations={report['environment']['iterations_per_repetition']} "
          f"auto_scalar_backend={report['environment']['keylab_auto_scalar_backend']}")
    print("\nMSM: random scalar / random point distribution")
    print(f"{'n':>4} {'method':<24} {'median ms':>12} {'ns/pair':>12} {'speedup':>9}")
    for row in report["msm"]:
        if row["distribution"] == "random":
            print(
                f"{row['batch_size']:>4} {row['method']:<24} "
                f"{float(row['median_ns']) / 1e6:>12.3f} "
                f"{float(row['time_per_pair_ns']):>12.0f} "
                f"{float(row['speedup_vs_naive_python']):>8.2f}x"
            )
    print("\nBIP-340: valid distinct-key batches")
    print(
        f"{'n':>4} {'individual ms':>14} {'batch ms':>12} "
        f"{'native ms':>12} {'ns/signature':>14} {'Python batch/ind':>18}"
    )
    for size in report["sizes"]:
        rows = [r for r in report["schnorr"] if
                r["scenario"] == "valid-distinct" and r["batch_size"] == size]
        individual = next(r for r in rows if r["mode"] == "individual")
        batch = next(r for r in rows if r["mode"] == "batch-csprng")
        native = next(
            (r for r in rows if r["mode"] == "native-individual-libsecp256k1"),
            None,
        )
        print(
            f"{size:>4} {float(individual['median_ns']) / 1e6:>14.3f} "
            f"{float(batch['median_ns']) / 1e6:>12.3f} "
            f"{float(native['median_ns']) / 1e6 if native else 0.0:>12.3f} "
            f"{float(batch['average_ns_per_signature']):>14.0f} "
            f"{float(batch['speedup_vs_individual_total']):>18.2f}x"
        )
    print("\nIndependent Coincurve checks:", json.dumps(report["coincurve_preflight"], sort_keys=True))
    print("\nComponent profile at largest configured batch:")
    largest = max(report["sizes"])
    component_rows = [
        row for row in report["components"]
        if row["batch_size"] == largest
    ]
    print(f"{'component':<38} {'median ms':>12}")
    for row in sorted(component_rows, key=lambda item: str(item["component"])):
        print(
            f"{row['component']:<38} "
            f"{float(row['median_ns']) / 1e6:>12.3f}"
        )


def run_benchmarks(
    *,
    seed: int = 20261122,
    sizes: Sequence[int] = DEFAULT_SIZES,
    msm_distributions: Sequence[str] = MSM_DISTRIBUTIONS,
    schnorr_scenarios: Sequence[str] = SCHNORR_SCENARIOS,
    repetitions: int = 5,
    iterations: int = 1,
    component_repetitions: int = 20,
) -> dict[str, Any]:
    _validate_sizes(sizes)
    msm_rows = benchmark_msm(
        seed=seed, sizes=sizes, distributions=msm_distributions,
        repetitions=repetitions, iterations=iterations,
    )
    schnorr_rows, native_preflight = benchmark_schnorr(
        seed=seed, sizes=sizes, scenarios=schnorr_scenarios,
        repetitions=repetitions, iterations=iterations,
    )
    component_rows = benchmark_verification_components(
        seed=seed,
        sizes=sizes,
        repetitions=component_repetitions,
        iterations=iterations,
    )
    return {
        "benchmark": "keylab-msm-and-bip340-batch-verification",
        "environment": _environment(
            seed,
            repetitions,
            iterations,
            component_repetitions,
        ),
        "sizes": list(sizes),
        "msm_distributions": list(msm_distributions),
        "schnorr_scenarios": list(schnorr_scenarios),
        "msm": msm_rows,
        "schnorr": schnorr_rows,
        "components": component_rows,
        "coincurve_preflight": native_preflight,
        "native_backend_capabilities": {
            "coincurve_schnorr_individual_verify": (
                native_preflight["available"]
            ),
            "coincurve_schnorr_batch_verify": False,
            "coincurve_msm_api": False,
            "evidence": native_preflight["batch_api_evidence"],
        },
        "performance_analysis": _performance_analysis(msm_rows, schnorr_rows),
        "message_lengths_bytes": list(MESSAGE_LENGTHS),
        "method_notes": {
            "naive-python-glv": "Sum of per-term python-glv scalar multiplications and affine additions.",
            "straus-glv-wnaf": "Existing Straus MSM; internally uses GLV decomposition and interleaved wNAF.",
            "batch-csprng": "Production batch API; coefficients generated from secrets for every invocation.",
            "batch-fixed-coefficients": (
                "Deterministic coefficient mode for repeatability only; it is not production verification."
            ),
            "individual": "Checks every member separately without short-circuiting invalid batches.",
            "native-individual-libsecp256k1": (
                "Coincurve/PublicKeyXOnly individual verification; "
                "native public-key objects are preconstructed outside timed operations."
            ),
            "native-batch": (
                "Unavailable: Coincurve 19.0.1 exposes no native batch Schnorr API."
            ),
        },
    }


def _write_csv(path: Path, report: dict[str, Any]) -> None:
    rows = report["msm"] + report["schnorr"] + report["components"]
    columns = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _performance_analysis(
    msm_rows: Sequence[dict[str, Any]],
    schnorr_rows: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    msm_observed_crossover: dict[str, dict[str, int | None]] = {}
    distributions = sorted({str(row["distribution"]) for row in msm_rows})
    methods = sorted({str(row["method"]) for row in msm_rows})
    for distribution in distributions:
        msm_observed_crossover[distribution] = {}
        for method in methods:
            faster = [
                int(row["batch_size"])
                for row in msm_rows
                if row["distribution"] == distribution
                and row["method"] == method
                and row["speedup_vs_naive_python"] is not None
                and float(row["speedup_vs_naive_python"]) > 1
            ]
            msm_observed_crossover[distribution][method] = min(faster) if faster else None

    valid_batch_speedups = [
        row for row in schnorr_rows
        if row["scenario"] == "valid-distinct" and row["mode"] == "batch-csprng"
    ]
    valid_fixed_speedups = [
        row for row in schnorr_rows
        if row["scenario"] == "valid-distinct" and row["mode"] == "batch-fixed-coefficients"
    ]
    invalid_batch_degradation: dict[str, dict[str, float | None]] = {}
    for scenario in ("invalid-first", "invalid-middle", "invalid-last", "malformed-middle"):
        invalid_batch_degradation[scenario] = {
            str(row["batch_size"]): row["invalid_batch_time_ratio_vs_valid"]
            for row in schnorr_rows
            if row["scenario"] == scenario
            and row["mode"] == "batch-csprng"
        }

    return {
        "speedup_definition": "baseline median ns / comparison median ns",
        "msm_observed_crossover_vs_naive_python": msm_observed_crossover,
        "batch_csprng_observed_crossover_vs_individual": min(
            (int(row["batch_size"]) for row in valid_batch_speedups
             if float(row["speedup_vs_individual_total"]) > 1),
            default=None,
        ),
        "batch_fixed_coefficient_observed_crossover_vs_individual": min(
            (int(row["batch_size"]) for row in valid_fixed_speedups
             if float(row["speedup_vs_individual_total"]) > 1),
            default=None,
        ),
        "invalid_batch_degradation": invalid_batch_degradation,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261122)
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--component-repetitions", type=int, default=20)
    parser.add_argument("--smoke", action="store_true", help="run a quick correctness/timing smoke subset")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--csv-output", type=Path)
    args = parser.parse_args(argv)
    try:
        sizes = tuple(int(value) for value in args.sizes.split(",") if value)
    except ValueError:
        parser.error("--sizes must be a comma-separated list of integers")
    _validate_sizes(sizes)
    if (
        args.seed < 0
        or args.repetitions < 2
        or args.component_repetitions < 2
        or args.iterations < 1
    ):
        parser.error(
            "--seed must be nonnegative, repetitions >= 2, "
            "component-repetitions >= 2, and iterations positive"
        )

    if args.smoke:
        sizes = tuple(size for size in sizes if size in (1, 2)) or (1, 2)
        distributions = ("random", "zero-heavy", "repeated-points")
        scenarios = (
            "valid-distinct",
            "valid-repeated-key",
            "invalid-first",
            "invalid-middle",
            "invalid-last",
            "malformed-middle",
        )
    else:
        distributions = MSM_DISTRIBUTIONS
        scenarios = SCHNORR_SCENARIOS

    report = run_benchmarks(
        seed=args.seed,
        sizes=sizes,
        msm_distributions=distributions,
        schnorr_scenarios=scenarios,
        repetitions=args.repetitions,
        iterations=args.iterations,
        component_repetitions=args.component_repetitions,
    )
    _summary_table(report)
    if args.json_output:
        args.json_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"\nJSON report: {args.json_output}")
    if args.csv_output:
        _write_csv(args.csv_output, report)
        print(f"CSV measurements: {args.csv_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
