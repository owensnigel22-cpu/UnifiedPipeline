"""Small reproducible performance probes for public-key conversion paths."""

from __future__ import annotations

import hashlib
import platform
import random
import secrets
import sys
from collections.abc import Iterable
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path
from time import perf_counter_ns

from keylab.ec.secp256k1 import (
    _INFINITY,
    G,
    N,
    _to_affine,
    _to_jacobian,
    compress_pubkey,
    is_on_curve,
    point_add,
    point_double,
    scalar_mult,
)
from keylab.encoding.address import (
    hash160,
    p2pkh_address,
    p2sh_p2wpkh_address,
    p2wpkh_address,
)
from keylab.encoding.taproot import taproot_output_from_point
from keylab.encoding.wif import decode as decode_wif
from keylab.encoding.wif import encode as encode_wif


@lru_cache(maxsize=1)
def _v65_fixed_base_table() -> tuple[tuple[tuple[int, int, int], ...], ...]:
    """Build the 64-window Jacobian table used by the attached v65 script."""
    windows = []
    base = _to_jacobian(G)
    for _ in range(64):
        multiples = [_INFINITY]
        current = base
        for _digit in range(1, 16):
            multiples.append(current)
            current = point_add(current, base)
        windows.append(tuple(multiples))
        for _ in range(4):
            base = point_double(base)
    return tuple(windows)


def _v65_fixed_base_mult(scalar: int) -> tuple[int, int] | None:
    """Run v65's precomputed, low-nibble-first fixed-base window algorithm."""
    result = _INFINITY
    for window_index, multiples in enumerate(_v65_fixed_base_table()):
        digit = (scalar >> (4 * window_index)) & 0xF
        if digit:
            result = point_add(result, multiples[digit])
    return _to_affine(result)


def benchmark_ec(
    *,
    count: int = 12,
    seed: int = 20261020,
    repetitions: int = 5,
    backend: str = "all",
) -> dict[str, object]:
    """Compare generator multiplication on one seeded corpus with median timings.

    The ``v65-windowed`` method ports the attached monolith's 64-position,
    4-bit Jacobian table algorithm into this benchmark. Setup and correctness
    checks are excluded from measured repetitions. No scalars are returned.
    """
    if type(count) is not int or count < 1:
        raise ValueError("count must be a positive integer")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    available = ("python", "python-affine-window", "python-glv", "python-wnaf", "v65-windowed") + tuple(
        name for name in ("coincurve", "fastecdsa") if find_spec(name) is not None
    )
    methods = available if backend == "all" else (backend,)
    if backend != "all" and backend not in available:
        raise ValueError(f"unsupported or unavailable backend {backend!r}; choose from {available}")

    rng = random.Random(seed)
    scalars = tuple(rng.randrange(1, N) for _ in range(count))
    references = tuple(scalar_mult(scalar, backend="python") for scalar in scalars)
    if any(point is None for point in references):
        raise ArithmeticError("reference multiplication unexpectedly produced infinity")

    _v65_fixed_base_table.cache_clear()
    setup_started = perf_counter_ns()
    _v65_fixed_base_table()
    v65_table_setup_ms = (perf_counter_ns() - setup_started) / 1_000_000

    functions = {
        "v65-windowed": _v65_fixed_base_mult,
        **{name: (lambda scalar, name=name: scalar_mult(scalar, backend=name)) for name in available if name != "v65-windowed"},
    }
    warmup_ms: dict[str, float] = {}
    for name in methods:
        started = perf_counter_ns()
        # Warm lazy tables/native imports, then verify output for the full shared corpus.
        functions[name](scalars[0])
        warmup_ms[name] = (perf_counter_ns() - started) / 1_000_000
        for scalar, reference in zip(scalars, references, strict=True):
            if functions[name](scalar) != reference:
                raise ArithmeticError(f"{name} produced a public point different from the Python reference")

    elapsed_by_method: dict[str, list[int]] = {name: [] for name in methods}
    order_rng = random.Random(seed ^ 0x4B65794C61624543)
    for _ in range(repetitions):
        method_order = list(methods)
        order_rng.shuffle(method_order)
        for name in method_order:
            started = perf_counter_ns()
            for scalar in scalars:
                functions[name](scalar)
            elapsed_by_method[name].append(perf_counter_ns() - started)

    rows = []
    for name in methods:
        samples = sorted(elapsed_by_method[name])
        middle = len(samples) // 2
        median_ns = (
            samples[middle]
            if len(samples) % 2
            else (samples[middle - 1] + samples[middle]) / 2
        )
        rows.append(
            {
                "method": name,
                "median_ms_per_corpus": median_ns / 1_000_000,
                "median_keys_per_second": count * 1_000_000_000 / median_ns,
                "samples_ms": [elapsed / 1_000_000 for elapsed in elapsed_by_method[name]],
                "warmup_ms_excluded": warmup_ms[name],
                "outputs_match_reference": True,
            }
        )
    return {
        "benchmark": "secp256k1-generator-scalar-multiplication",
        "count": count,
        "seed": seed,
        "repetitions": repetitions,
        "timing_statistic": "median elapsed time over the same scalar corpus",
        "v65_table_setup_ms_excluded": v65_table_setup_ms,
        "methods": rows,
        "machine": platform.platform(),
        "python_version": sys.version.split()[0],
        "note": "The v65-windowed row is the v65 algorithm ported into Keylab's Jacobian primitives; scalar values are intentionally omitted.",
    }


def benchmark_wif_to_pubkey(
    iterations: int = 1_000,
    *,
    warmup: int = 20,
    backend: str = "auto",
) -> dict[str, object]:
    """Time WIF decode, scalar parse, secp256k1 multiplication, compression, and hex.

    The benchmark uses a deterministic public test fixture with a full-width
    scalar, never prints/returns its WIF or scalar, and reports per-stage
    measurements plus total throughput. Measurements are diagnostic; machine,
    Python, and backend versions affect the result.
    """
    if type(iterations) is not int or iterations < 1:
        raise ValueError("iterations must be a positive integer")
    if type(warmup) is not int or warmup < 0:
        raise ValueError("warmup must be a nonnegative integer")
    if backend not in {
        "auto", "python", "python-affine-window", "python-glv", "python-wnaf", "coincurve", "fastecdsa"
    }:
        raise ValueError("unsupported scalar multiplication backend")

    scalar_fixture = int.from_bytes(hashlib.sha256(b"Keylab public benchmark fixture v1").digest(), "big") % (N - 1) + 1
    wif = encode_wif(scalar_fixture, compressed=True)
    reference_point = scalar_mult(scalar_fixture, backend="python")
    if reference_point is None:
        raise ArithmeticError("benchmark fixture unexpectedly produced the point at infinity")
    reference_hex = compress_pubkey(reference_point).hex()
    for _ in range(warmup):
        key_bytes, _, _ = decode_wif(wif)
        point = scalar_mult(int.from_bytes(key_bytes, "big"), backend=backend)
        if point is None:
            raise ArithmeticError("test scalar unexpectedly produced the point at infinity")
        compress_pubkey(point).hex()

    stages = {name: 0 for name in ("wif_decode", "scalar_parse", "scalar_multiplication", "compression", "hex_encoding")}
    started = perf_counter_ns()
    measured_hex = ""
    for _ in range(iterations):
        t0 = perf_counter_ns()
        key_bytes, compressed, network = decode_wif(wif)
        stages["wif_decode"] += perf_counter_ns() - t0
        if not compressed or network != "mainnet":
            raise ArithmeticError("benchmark WIF fixture failed validation")

        t0 = perf_counter_ns()
        scalar = int.from_bytes(key_bytes, "big")
        stages["scalar_parse"] += perf_counter_ns() - t0

        t0 = perf_counter_ns()
        point = scalar_mult(scalar, backend=backend)
        stages["scalar_multiplication"] += perf_counter_ns() - t0
        if point is None:
            raise ArithmeticError("test scalar unexpectedly produced the point at infinity")

        t0 = perf_counter_ns()
        serialized = compress_pubkey(point)
        stages["compression"] += perf_counter_ns() - t0

        t0 = perf_counter_ns()
        measured_hex = serialized.hex()
        stages["hex_encoding"] += perf_counter_ns() - t0
    elapsed = perf_counter_ns() - started
    if measured_hex != reference_hex:
        raise ArithmeticError("benchmark output did not match the Python reference public key")

    return {
        "backend": backend,
        "iterations": iterations,
        "warmup": warmup,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "elapsed_ms": elapsed / 1_000_000,
        "average_ms_per_op": elapsed / iterations / 1_000_000,
        "throughput_per_second": iterations * 1_000_000_000 / elapsed,
        "stages_ms": {name: duration / 1_000_000 for name, duration in stages.items()},
        "stages_percent_of_total": {name: 100 * duration / elapsed for name, duration in stages.items()},
        "unattributed_percent": max(0.0, 100 * (elapsed - sum(stages.values())) / elapsed),
        "reference_pubkey_hex": reference_hex,
        "measurement_note": "Machine-dependent diagnostic; remeasure before citing throughput claims.",
    }


def available_scalar_backends() -> tuple[str, ...]:
    """List explicit scalar backends currently importable on this machine."""
    return ("python", "python-affine-window", "python-glv", "python-wnaf") + tuple(
        name for name in ("coincurve", "fastecdsa") if find_spec(name) is not None
    )


def benchmark_multiple_wifs(
    wifs: Iterable[str],
    *,
    backend: str = "auto",
    derive_addresses: bool = True,
    address_types: Iterable[str] | None = None,
    warmup: int = 3,
    corpus_source: str = "provided",
) -> dict[str, object]:
    """Profile independent WIFs without printing or returning keys or addresses.

    Corpus construction/loading and warmup are excluded from timed stages. The
    address stage measures P2PKH and Taproot for all keys, plus nested and native
    SegWit addresses for compressed WIFs.
    """
    valid_backends = {"auto", *available_scalar_backends()}
    if backend not in valid_backends:
        raise ValueError(f"unsupported backend {backend!r}; choose from {sorted(valid_backends)}")
    if type(warmup) is not int or warmup < 0:
        raise ValueError("warmup must be a nonnegative integer")
    all_address_types = ("p2pkh", "p2sh_p2wpkh", "p2wpkh", "p2tr")
    selected_address_types = set(all_address_types if address_types is None else address_types)
    unknown_address_types = selected_address_types.difference(all_address_types)
    if unknown_address_types:
        raise ValueError(f"unsupported address types: {sorted(unknown_address_types)}")
    corpus = tuple(wifs)
    if not corpus:
        raise ValueError("WIF corpus must contain at least one key")

    if warmup:
        warm_key, _, _ = decode_wif(corpus[0])
        for _ in range(warmup):
            warm_point = scalar_mult(int.from_bytes(warm_key, "big"), backend=backend)
            if warm_point is None:
                raise ArithmeticError("warmup scalar unexpectedly produced infinity")

    stage_names = ("wif_decode", "scalar_parse", "scalar_multiplication", "serialization", "address_generation")
    stages = dict.fromkeys(stage_names, 0)
    address_stages = dict.fromkeys(("p2pkh", "p2sh_p2wpkh", "p2wpkh", "p2tr"), 0)
    address_counts = dict.fromkeys(address_stages, 0)
    address_count = 0
    started = perf_counter_ns()
    for item_index, wif in enumerate(corpus, start=1):
        try:
            t0 = perf_counter_ns()
            key_bytes, compressed, network = decode_wif(wif)
            stages["wif_decode"] += perf_counter_ns() - t0
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid WIF at corpus item {item_index}: {exc}") from exc

        t0 = perf_counter_ns()
        scalar = int.from_bytes(key_bytes, "big")
        stages["scalar_parse"] += perf_counter_ns() - t0

        t0 = perf_counter_ns()
        point = scalar_mult(scalar, backend=backend)
        stages["scalar_multiplication"] += perf_counter_ns() - t0
        if point is None or not is_on_curve(point):
            raise ArithmeticError(f"public-key derivation failed at corpus item {item_index}")

        t0 = perf_counter_ns()
        public_key = (
            compress_pubkey(point)
            if compressed
            else b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        )
        stages["serialization"] += perf_counter_ns() - t0

        if derive_addresses and selected_address_types:
            address_started = perf_counter_ns()
            if "p2pkh" in selected_address_types:
                t0 = perf_counter_ns()
                p2pkh_address(public_key, network)
                address_stages["p2pkh"] += perf_counter_ns() - t0
                address_count += 1
                address_counts["p2pkh"] += 1
            if compressed and "p2sh_p2wpkh" in selected_address_types:
                t0 = perf_counter_ns()
                p2sh_p2wpkh_address(public_key, network)
                address_stages["p2sh_p2wpkh"] += perf_counter_ns() - t0
                address_count += 1
                address_counts["p2sh_p2wpkh"] += 1
            if compressed and "p2wpkh" in selected_address_types:
                t0 = perf_counter_ns()
                p2wpkh_address(public_key, network)
                address_stages["p2wpkh"] += perf_counter_ns() - t0
                address_count += 1
                address_counts["p2wpkh"] += 1
            if "p2tr" in selected_address_types:
                t0 = perf_counter_ns()
                taproot_output_from_point(point, network=network)
                address_stages["p2tr"] += perf_counter_ns() - t0
                address_count += 1
                address_counts["p2tr"] += 1
            stages["address_generation"] += perf_counter_ns() - address_started
    elapsed = perf_counter_ns() - started
    return {
        "benchmark": "multiple-wif-to-public-keys-and-addresses",
        "corpus_source": corpus_source,
        "keys_processed": len(corpus),
        "addresses_derived": address_count if derive_addresses else None,
        "address_types_selected": sorted(selected_address_types) if derive_addresses else [],
        "address_counts": address_counts if derive_addresses else None,
        "backend": backend,
        "warmup": warmup,
        "derive_addresses": derive_addresses,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "elapsed_ms": elapsed / 1_000_000,
        "average_ms_per_key": elapsed / len(corpus) / 1_000_000,
        "throughput_per_second": len(corpus) * 1_000_000_000 / elapsed,
        "stages_ms": {name: duration / 1_000_000 for name, duration in stages.items()},
        "stages_percent_of_total": {name: 100 * duration / elapsed for name, duration in stages.items()},
        "address_types_ms": {name: duration / 1_000_000 for name, duration in address_stages.items()},
        "address_types_percent_of_total": {
            name: 100 * duration / elapsed for name, duration in address_stages.items()
        },
        "address_types_us_per_address": {
            name: (address_stages[name] / address_counts[name] / 1_000 if address_counts[name] else None)
            for name in address_stages
        },
        "unattributed_percent": max(0.0, 100 * (elapsed - sum(stages.values())) / elapsed),
        "measurement_note": "Machine-dependent diagnostic; corpus loading and warmup are excluded; secrets and derived addresses are not returned.",
    }


def benchmark_synthetic_wifs(
    count: int = 1_000,
    *,
    backend: str = "auto",
    derive_addresses: bool = True,
    address_types: Iterable[str] | None = None,
    warmup: int = 3,
) -> dict[str, object]:
    """Create a random synthetic WIF corpus, then benchmark without printing keys."""
    if type(count) is not int or not 1 <= count <= 1_000_000:
        raise ValueError("count must be between 1 and 1,000,000")
    wifs = (encode_wif(secrets.randbelow(N - 1) + 1, compressed=True) for _ in range(count))
    return benchmark_multiple_wifs(
        wifs,
        backend=backend,
        derive_addresses=derive_addresses,
        address_types=address_types,
        warmup=warmup,
        corpus_source="synthetic-random",
    )


def benchmark_hash160_only(count: int = 10_000, *, backend: str = "auto") -> dict[str, object]:
    """Measure HASH160 on unique valid compressed public-key fixtures.

    Fixture generation is excluded from the hash timer and reported separately.
    """
    valid_backends = {"auto", *available_scalar_backends()}
    if backend not in valid_backends:
        raise ValueError(f"unsupported backend {backend!r}; choose from {sorted(valid_backends)}")
    if type(count) is not int or not 1 <= count <= 100_000:
        raise ValueError("count must be between 1 and 100,000")

    setup_started = perf_counter_ns()
    public_keys: list[bytes] = []
    for index in range(count):
        seed = hashlib.sha256(b"Keylab HASH160 benchmark v1" + index.to_bytes(8, "big")).digest()
        scalar = int.from_bytes(seed, "big") % (N - 1) + 1
        point = scalar_mult(scalar, backend=backend)
        if point is None:
            raise ArithmeticError("HASH160 benchmark fixture unexpectedly produced infinity")
        public_keys.append(compress_pubkey(point))
    setup_elapsed = perf_counter_ns() - setup_started

    for public_key in public_keys[: min(100, count)]:
        hash160(public_key)
    started = perf_counter_ns()
    digest_bytes = 0
    for public_key in public_keys:
        digest_bytes += len(hash160(public_key))
    elapsed = perf_counter_ns() - started
    return {
        "benchmark": "hash160-compressed-public-keys",
        "keys_processed": count,
        "backend_for_fixture_generation": backend,
        "setup_ms_excluded_from_hash_timing": setup_elapsed / 1_000_000,
        "elapsed_ms": elapsed / 1_000_000,
        "average_us_per_hash": elapsed / count / 1_000,
        "throughput_per_second": count * 1_000_000_000 / elapsed,
        "digest_bytes_checked": digest_bytes,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "measurement_note": "Unique valid compressed public-key fixtures; key generation and warmup are excluded from HASH160 timing.",
    }


def benchmark_wif_file(
    path: str | Path,
    *,
    backend: str = "auto",
    derive_addresses: bool = True,
    address_types: Iterable[str] | None = None,
    warmup: int = 3,
) -> dict[str, object]:
    """Benchmark nonblank, noncomment WIF lines from a local text file."""
    try:
        with Path(path).open("r", encoding="utf-8") as input_file:
            wifs = [line.strip() for line in input_file if line.strip() and not line.lstrip().startswith("#")]
    except OSError as exc:
        raise ValueError(f"could not read WIF corpus file: {exc}") from exc
    return benchmark_multiple_wifs(
        wifs,
        backend=backend,
        derive_addresses=derive_addresses,
        address_types=address_types,
        warmup=warmup,
        corpus_source="file",
    )


__all__ = [
    "available_scalar_backends",
    "benchmark_ec",
    "benchmark_hash160_only",
    "benchmark_multiple_wifs",
    "benchmark_synthetic_wifs",
    "benchmark_wif_file",
    "benchmark_wif_to_pubkey",
]
