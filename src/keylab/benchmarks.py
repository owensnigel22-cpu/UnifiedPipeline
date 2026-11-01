"""Small reproducible performance probes for public-key conversion paths."""

from __future__ import annotations

import hashlib
import platform
import random
import secrets
import sys
from collections.abc import Callable, Iterable
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path
from statistics import median
from time import perf_counter_ns

from keylab.ec.secp256k1 import (
    _INFINITY,
    G,
    N,
    _to_affine,
    _to_jacobian,
    compress_pubkey,
    decompress_pubkey,
    is_on_curve,
    point_add,
    point_add_affine,
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
    # The frozen textbook oracle (keylab.ec.reference), independent of every method timed here.
    references = tuple(scalar_mult(scalar, backend="python-reference") for scalar in scalars)
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
                raise ArithmeticError(f"{name} produced a public point different from keylab.ec.reference")

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
        "reference_implementation": "keylab.ec.reference",
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
    repetitions: int = 1,
) -> dict[str, object]:
    """Create a random synthetic WIF corpus, then benchmark without printing keys."""
    if type(count) is not int or not 1 <= count <= 1_000_000:
        raise ValueError("count must be between 1 and 1,000,000")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    wifs = tuple(encode_wif(secrets.randbelow(N - 1) + 1, compressed=True) for _ in range(count))
    return benchmark_repeated_wifs(
        wifs,
        repetitions=repetitions,
        backend=backend,
        derive_addresses=derive_addresses,
        address_types=address_types,
        warmup=warmup,
        corpus_source="synthetic-random",
    )


def benchmark_repeated_wifs(
    wifs: Iterable[str],
    *,
    repetitions: int = 5,
    backend: str = "auto",
    derive_addresses: bool = True,
    address_types: Iterable[str] | None = None,
    warmup: int = 3,
    corpus_source: str = "provided",
) -> dict[str, object]:
    """Benchmark one fixed WIF corpus repeatedly and report median timings."""
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    corpus = tuple(wifs)
    if not corpus:
        raise ValueError("WIF corpus must contain at least one key")
    runs = [
        benchmark_multiple_wifs(
            corpus,
            backend=backend,
            derive_addresses=derive_addresses,
            address_types=address_types,
            warmup=warmup,
            corpus_source=corpus_source,
        )
        for _ in range(repetitions)
    ]
    summary = dict(runs[0])
    median_elapsed_ns = median(float(run["elapsed_ms"]) for run in runs) * 1_000_000
    summary.update(
        repetitions=repetitions,
        elapsed_ms=median_elapsed_ns / 1_000_000,
        average_ms_per_key=median_elapsed_ns / len(corpus) / 1_000_000,
        throughput_per_second=median(float(run["throughput_per_second"]) for run in runs),
        stages_ms={
            name: median(float(run["stages_ms"][name]) for run in runs)
            for name in runs[0]["stages_ms"]
        },
        address_types_ms={
            name: median(float(run["address_types_ms"][name]) for run in runs)
            for name in runs[0]["address_types_ms"]
        },
        run_timings=[
            {
                "elapsed_ms": run["elapsed_ms"],
                "throughput_per_second": run["throughput_per_second"],
                "address_types_us_per_address": run["address_types_us_per_address"],
            }
            for run in runs
        ],
        measurement_note=(
            "Same WIF corpus reused across runs; corpus loading and warmup excluded; "
            "stage values are per-stage medians; secrets and derived addresses are not returned."
        ),
    )
    median_elapsed_ms = median_elapsed_ns / 1_000_000
    summary["stages_percent_of_total"] = {
        name: 100 * duration / median_elapsed_ms
        for name, duration in summary["stages_ms"].items()
    }
    summary["address_types_percent_of_total"] = {
        name: 100 * duration / median_elapsed_ms
        for name, duration in summary["address_types_ms"].items()
    }
    counts = runs[0]["address_counts"]
    summary["address_types_us_per_address"] = (
        {
            name: (duration * 1_000 / counts[name] if counts[name] else None)
            for name, duration in summary["address_types_ms"].items()
        }
        if counts is not None
        else {name: None for name in summary["address_types_ms"]}
    )
    return summary


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
    repetitions: int = 1,
) -> dict[str, object]:
    """Benchmark nonblank, noncomment WIF lines from a local text file."""
    try:
        with Path(path).open("r", encoding="utf-8") as input_file:
            wifs = [line.strip() for line in input_file if line.strip() and not line.lstrip().startswith("#")]
    except OSError as exc:
        raise ValueError(f"could not read WIF corpus file: {exc}") from exc
    return benchmark_repeated_wifs(
        wifs,
        repetitions=repetitions,
        backend=backend,
        derive_addresses=derive_addresses,
        address_types=address_types,
        warmup=warmup,
        corpus_source="file",
    )


SIGNATURE_OPERATIONS = (
    "schnorr-sign",
    "schnorr-verify",
    "ecdsa-sign",
    "ecdsa-verify",
    "bip32-ckdpriv",
    "bip32-ckdpub",
    "taproot-tweak-pubkey",
    "taproot-tweak-seckey",
    "taproot-sign",
    "musig2-key-agg",
)


MUSIG2_GROUP_SIZE = 3


def _median_ns(samples: list[int]) -> float:
    ordered = sorted(samples)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def benchmark_signatures(
    *,
    count: int = 8,
    seed: int = 20261030,
    repetitions: int = 5,
    backend: str = "all",
) -> dict[str, object]:
    """Time BIP-340, ECDSA, BIP-32, Taproot, and MuSig2 operations on a seeded public corpus.

    ``backend`` selects Keylab's implementations (``keylab``), the libsecp256k1
    reference through coincurve (``coincurve``), or both (``all``). Keylab rows
    use ``scalar_mult(backend="auto")``, so their point multiplications run on
    libsecp256k1 when coincurve is installed; ``keylab_multiplication`` in the
    report records which path was active.
    Every operation is checked for correctness before timing (Python and
    libsecp256k1 Schnorr signatures must be byte-identical), method order is
    shuffled per repetition, and medians are reported. Scalars, signatures,
    and keys are never included in the result.
    """
    from keylab.ec.musig2 import key_agg, key_agg_coeff, key_sort
    from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
    from keylab.ec.secp256k1 import ecdsa_sign_digest, ecdsa_verify_digest
    from keylab.encoding.taproot import taproot_output, taproot_sign_key_path, taproot_tweak_seckey
    from keylab.hd import ExtendedKey

    if type(count) is not int or count < 1:
        raise ValueError("count must be a positive integer")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if backend not in ("all", "keylab", "coincurve"):
        raise ValueError("backend must be 'all', 'keylab', or 'coincurve'")
    have_coincurve = find_spec("coincurve") is not None
    if backend == "coincurve" and not have_coincurve:
        raise ImportError("install Keylab's coincurve extra: pip install 'keylab[secp256k1]'")

    rng = random.Random(seed)
    scalars = tuple(rng.randrange(1, N) for _ in range(count))
    messages = tuple(hashlib.sha256(seed.to_bytes(8, "big") + i.to_bytes(4, "big")).digest()
                     for i in range(count))
    aux = tuple(hashlib.sha256(b"aux" + message).digest() for message in messages)
    xonly = tuple(schnorr_public_key(scalar) for scalar in scalars)
    points = tuple(scalar_mult(scalar, backend="python") for scalar in scalars)
    schnorr_sigs = tuple(schnorr_sign(m, d, a) for m, d, a in zip(messages, scalars, aux))
    ecdsa_sigs = tuple(ecdsa_sign_digest(m, d) for m, d in zip(messages, scalars))
    root = ExtendedKey.from_seed(rng.randbytes(32))
    account = root.derive("m/86'/0'/0'")
    account_public = account.neuter()
    merkle_root = hashlib.sha256(b"keylab benchmark tree").digest()
    corpus = range(count)
    # MuSig2: one KeyAgg over a sorted group of MUSIG2_GROUP_SIZE plain keys per operation.
    plain_keys = tuple(compress_pubkey(point) for point in points)
    musig_groups = tuple(
        key_sort([plain_keys[(i + j) % count] for j in range(MUSIG2_GROUP_SIZE)]) for i in corpus
    )

    functions: dict[tuple[str, str], object] = {}
    if backend in ("all", "keylab"):
        functions.update({
            ("schnorr-sign", "keylab"): lambda i: schnorr_sign(messages[i], scalars[i], aux[i]),
            ("schnorr-verify", "keylab"): lambda i: schnorr_verify(messages[i], schnorr_sigs[i], xonly[i]),
            ("ecdsa-sign", "keylab"): lambda i: ecdsa_sign_digest(messages[i], scalars[i]),
            ("ecdsa-verify", "keylab"): lambda i: ecdsa_verify_digest(messages[i], ecdsa_sigs[i], points[i]),
            ("bip32-ckdpriv", "keylab"): lambda i: account.child(i),
            ("bip32-ckdpub", "keylab"): lambda i: account_public.child(i),
            ("taproot-tweak-pubkey", "keylab"): lambda i: taproot_output(xonly[i], merkle_root),
            ("taproot-tweak-seckey", "keylab"): lambda i: taproot_tweak_seckey(scalars[i], merkle_root),
            ("taproot-sign", "keylab"): lambda i: taproot_sign_key_path(
                messages[i], scalars[i], merkle_root, aux_rand=aux[i]),
            ("musig2-key-agg", "keylab"): lambda i: key_agg(musig_groups[i]),
        })
    if backend in ("all", "coincurve") and have_coincurve:
        import coincurve

        cc_keys = tuple(coincurve.PrivateKey(scalar.to_bytes(32, "big")) for scalar in scalars)
        cc_xonly = tuple(coincurve.keys.PublicKeyXOnly(key) for key in xonly)
        cc_public = tuple(key.public_key for key in cc_keys)
        cc_ecdsa = tuple(key.sign(message, hasher=None) for key, message in zip(cc_keys, messages))
        functions.update({
            ("schnorr-sign", "libsecp256k1"): lambda i: cc_keys[i].sign_schnorr(messages[i], aux[i]),
            ("schnorr-verify", "libsecp256k1"): lambda i: cc_xonly[i].verify(schnorr_sigs[i], messages[i]),
            ("ecdsa-sign", "libsecp256k1"): lambda i: cc_keys[i].sign(messages[i], hasher=None),
            ("ecdsa-verify", "libsecp256k1"): lambda i: cc_public[i].verify(cc_ecdsa[i], messages[i], hasher=None),
        })
        for i in corpus:  # libsecp256k1 must agree with Keylab before anything is timed
            if cc_keys[i].sign_schnorr(messages[i], aux[i]) != schnorr_sigs[i]:
                raise ArithmeticError("libsecp256k1 and Keylab BIP-340 signatures differ")
            if not cc_public[i].verify(cc_ecdsa[i], messages[i], hasher=None):
                raise ArithmeticError("libsecp256k1 rejected its own ECDSA signature")
    if not functions:
        raise ValueError("no implementations selected")

    for i in corpus:  # correctness gate for Keylab's implementations
        if points[i] != scalar_mult(scalars[i], backend="python-reference"):
            raise ArithmeticError("public key differs from keylab.ec.reference")
        if not schnorr_verify(messages[i], schnorr_sigs[i], xonly[i]):
            raise ArithmeticError("BIP-340 signature failed verification")
        if not ecdsa_verify_digest(messages[i], ecdsa_sigs[i], points[i]):
            raise ArithmeticError("ECDSA signature failed verification")
        if account.child(i).neuter() != account_public.child(i):
            raise ArithmeticError("CKDpub disagrees with CKDpriv")
        tweaked = taproot_tweak_seckey(scalars[i], merkle_root)
        if schnorr_public_key(tweaked) != taproot_output(xonly[i], merkle_root).output_key_x:
            raise ArithmeticError("tweaked secret key does not match tweaked output key")
        group = musig_groups[i]
        expected_aggregate = None
        for member in group:  # independent sum of a_i * P_i
            expected_aggregate = point_add_affine(
                expected_aggregate,
                scalar_mult(key_agg_coeff(group, member), decompress_pubkey(member),
                            backend="python-reference"),
            )
        if key_agg(group).point != expected_aggregate:
            raise ArithmeticError("BIP-327 KeyAgg disagrees with the coefficient-wise sum")

    warmup_ms: dict[tuple[str, str], float] = {}
    for key, function in functions.items():
        started = perf_counter_ns()
        function(0)  # type: ignore[operator]
        warmup_ms[key] = (perf_counter_ns() - started) / 1_000_000

    samples: dict[tuple[str, str], list[int]] = {key: [] for key in functions}
    order_rng = random.Random(seed ^ 0x5349474E)
    for _ in range(repetitions):
        order = list(functions)
        order_rng.shuffle(order)
        for key in order:
            function = functions[key]
            started = perf_counter_ns()
            for i in corpus:
                function(i)  # type: ignore[operator]
            samples[key].append(perf_counter_ns() - started)

    rows = []
    for operation in SIGNATURE_OPERATIONS:
        for implementation in ("keylab", "libsecp256k1"):
            key = (operation, implementation)
            if key not in samples:
                continue
            median_ns = _median_ns(samples[key])
            rows.append({
                "operation": operation,
                "implementation": implementation,
                "median_ms_per_corpus": median_ns / 1_000_000,
                "median_ops_per_second": count * 1_000_000_000 / median_ns,
                "median_us_per_op": median_ns / count / 1_000,
                "samples_ms": [value / 1_000_000 for value in samples[key]],
                "warmup_ms_excluded": warmup_ms[key],
            })
    return {
        "benchmark": "secp256k1-signatures-bip32-taproot",
        "count": count,
        "seed": seed,
        "repetitions": repetitions,
        "timing_statistic": "median elapsed time over the same seeded corpus",
        "operations": rows,
        "coincurve_available": have_coincurve,
        "keylab_multiplication": "auto: libsecp256k1 via coincurve" if have_coincurve else "auto: pure Python",
        "machine": platform.platform(),
        "python_version": sys.version.split()[0],
        "note": ("Correctness was verified before timing; the corpus is seeded and public. "
                 "Scalars, signatures, and keys are intentionally omitted."),
    }


def benchmark_mnemonic(count: int = 100, *, bits: int = 128, seed: int = 20261101) -> dict[str, object]:
    """Time BIP-39 entropy->mnemonic, mnemonic->entropy, and mnemonic->seed.

    Correctness-gated: every generated mnemonic must round-trip to its entropy
    before any timing is recorded. No secrets are printed; the seeded corpus is
    synthetic entropy, not a user wallet.
    """
    from keylab import mnemonic as _mnemonic

    if type(count) is not int or count < 1:
        raise ValueError("count must be a positive integer")
    if bits not in _mnemonic.VALID_ENTROPY_BITS:
        raise ValueError(f"bits must be one of {_mnemonic.VALID_ENTROPY_BITS}")
    rng = random.Random(seed)
    corpus = [rng.getrandbits(bits).to_bytes(bits // 8, "big") for _ in range(count)]
    phrases = [_mnemonic.entropy_to_mnemonic(e) for e in corpus]
    for entropy, phrase in zip(corpus, phrases, strict=True):  # correctness gate
        if _mnemonic.mnemonic_to_entropy(phrase) != entropy:
            raise ArithmeticError("BIP-39 mnemonic did not round-trip to its entropy")

    def _time(operation: Callable[[int], object]) -> float:
        start = perf_counter_ns()
        for index in range(count):
            operation(index)
        return (perf_counter_ns() - start) / count / 1000.0

    results = {
        "entropy_to_mnemonic_us": _time(lambda i: _mnemonic.entropy_to_mnemonic(corpus[i])),
        "mnemonic_to_entropy_us": _time(lambda i: _mnemonic.mnemonic_to_entropy(phrases[i])),
        "mnemonic_to_seed_us": _time(lambda i: _mnemonic.mnemonic_to_seed(phrases[i], "")),
    }
    return {
        "benchmark": "bip39-mnemonic",
        "count": count,
        "entropy_bits": bits,
        "seed": seed,
        "outputs_round_trip": True,
        "timings_us_per_op": {k: round(v, 2) for k, v in results.items()},
        "machine": platform.platform(),
        "python_version": sys.version.split()[0],
        "note": "Metrics only; synthetic entropy, no user secrets printed.",
    }


__all__ = [
    "MUSIG2_GROUP_SIZE",
    "SIGNATURE_OPERATIONS",
    "available_scalar_backends",
    "benchmark_ec",
    "benchmark_hash160_only",
    "benchmark_mnemonic",
    "benchmark_multiple_wifs",
    "benchmark_repeated_wifs",
    "benchmark_signatures",
    "benchmark_synthetic_wifs",
    "benchmark_wif_file",
    "benchmark_wif_to_pubkey",
]
