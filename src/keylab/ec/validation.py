"""Differential validation of secp256k1 implementations against the frozen reference.

Every M2 optimization must pass these checks (docs/PERFORMANCE_VALIDATION.md).
Each ``diff_*`` function compares one family of operations with
:mod:`keylab.ec.reference` and returns a list of :class:`Mismatch` records:
empty means the implementations agree on every input tried.
:func:`assert_no_mismatches` turns a non-empty list into a readable failure.

The validation contract names the implementations being compared:

- ``python-reference``: the frozen textbook oracle (``keylab.ec.reference``).
- ``python-optimized``: exactly what ``scalar_mult(backend="auto")`` runs when
  no native backend is installed. Optimizations change this path.
- ``coincurve`` / ``fastecdsa``: independent native implementations, compared
  whenever they are installed.

The other pure-Python strategies (``python``, ``python-affine-window``,
``python-glv``, ``python-wnaf``) are validated alongside them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from keylab.ec import reference
from keylab.ec import secp256k1 as curve
from keylab.ec.sec1 import parse_sec1, serialize_sec1, serialize_uncompressed, serialize_xonly

Point = tuple[int, int] | None

CONTRACT_BACKENDS = ("python-reference", "python-optimized", "coincurve", "fastecdsa")
PYTHON_STRATEGIES = ("python", "python-affine-window", "python-glv", "python-wnaf")
NATIVE_BACKENDS = ("coincurve", "fastecdsa")

# Scalars at the boundaries every multiplication strategy must handle: zero and
# the group order (infinity), values just above N (reduction), the halves of N,
# the GLV eigenvalue and its complement, powers of two around window and
# half-length boundaries, and inputs wider than 256 bits.
EDGE_SCALARS: tuple[int, ...] = tuple(dict.fromkeys((
    0, 1, 2, 3, 4, 7, 15, 16, 17, 31, 32, 255, 256,
    curve.N - 3, curve.N - 2, curve.N - 1, curve.N, curve.N + 1, curve.N + 2,
    2 * curve.N - 1, 2 * curve.N, 2 * curve.N + 1,
    (curve.N - 1) // 2, (curve.N + 1) // 2,
    curve.LAMBDA, curve.N - curve.LAMBDA, curve.LAMBDA * curve.LAMBDA % curve.N,
    2**127, 2**128 - 1, 2**128, 2**128 + 1, 2**129,
    2**255, 2**256 - 1, 2**256, 2**300 + 12345,
)))


@dataclass(frozen=True)
class Mismatch:
    """One input on which an implementation disagreed with the reference."""

    operation: str
    implementation: str
    inputs: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return (f"{self.operation} [{self.implementation}] on {self.inputs}: "
                f"expected {self.expected}, got {self.actual}")


def available_backends(*, include_strategies: bool = True) -> tuple[str, ...]:
    """Return the contract backends usable here (native ones only if installed)."""
    names = [name for name in CONTRACT_BACKENDS
             if name not in NATIVE_BACKENDS or curve._backend_installed(name)]
    if include_strategies:
        names.extend(PYTHON_STRATEGIES)
    return tuple(names)


def hashed_point(label: str) -> tuple[int, int]:
    """Return a deterministic finite point k*G with k derived from ``label``."""
    seed = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (curve.N - 1) + 1
    point = reference.scalar_mult(seed)
    assert point is not None
    return point


def edge_points() -> tuple[tuple[int, int], ...]:
    """Finite points that exercise special cases: G, -G, 2G, lambda*G, and hashed points."""
    g = curve.G
    endomorphism = (curve.BETA * g[0] % curve.P, g[1])  # lambda*G = (beta*x, y)
    doubled = reference.double(g)
    assert doubled is not None
    points = [g, (g[0], curve.P - g[1]), doubled, endomorphism]
    points += [hashed_point(f"keylab-validation-{index}") for index in range(4)]
    return tuple(points)


def _fmt(value: object) -> str:
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(v, int) for v in value):
        return f"({value[0]:#x}, {value[1]:#x})"
    if isinstance(value, bytes):
        return value.hex()
    return repr(value)


def _outcome(operation: Callable[..., object], *args: object, **kwargs: object) -> object:
    """Return ``operation(*args, **kwargs)``, or the exception type name, so errors compare too."""
    try:
        return operation(*args, **kwargs)
    except (ValueError, TypeError, ArithmeticError) as exc:
        return f"raises {type(exc).__name__}"


def diff_scalar_mult(
    scalars: Iterable[int] | None = None,
    points: Sequence[tuple[int, int]] | None = None,
    backends: Sequence[str] | None = None,
) -> list[Mismatch]:
    """Compare ``scalar_mult`` for every backend with the reference (defaults: edge inputs)."""
    scalars = EDGE_SCALARS if scalars is None else scalars
    points = edge_points() if points is None else points
    backends = available_backends() if backends is None else backends
    mismatches = []
    for scalar in scalars:
        for point in points:
            expected = reference.scalar_mult(scalar, point)
            for backend in backends:
                actual = _outcome(curve.scalar_mult, scalar, point, backend=backend)
                if actual != expected:
                    mismatches.append(Mismatch("scalar_mult", backend, f"k={scalar:#x}, P={_fmt(point)}",
                                               _fmt(expected), _fmt(actual)))
    return mismatches


def _jacobian_forms(point: Point) -> list[tuple[int, int, int]]:
    """Represent ``point`` with Z = 1 and with two non-trivial Z values."""
    if point is None:
        return [curve._INFINITY]
    x, y = point
    forms = []
    for z in (1, 2, curve.P - 3, 0xC0FFEE):
        forms.append((x * z * z % curve.P, y * z * z * z % curve.P, z))
    return forms


def diff_group_operations(points: Sequence[Point] | None = None) -> list[Mismatch]:
    """Compare addition, doubling, negation, mixed addition, and Jacobian conversion."""
    base: list[Point] = list(edge_points()) if points is None else list(points)
    candidates: list[Point] = [None, *base, *(reference.negate(p) for p in base)]
    mismatches = []

    def check(operation: str, inputs: str, expected: object, actual: object) -> None:
        if actual != expected:
            mismatches.append(Mismatch(operation, "keylab.ec.secp256k1", inputs, _fmt(expected), _fmt(actual)))

    for left in candidates:
        check("point_negate_affine", _fmt(left), reference.negate(left), curve.point_negate_affine(left))
        for form in _jacobian_forms(left):
            check("_to_affine(jacobian)", f"{form}", left, curve._to_affine(form))
            check("point_double(jacobian)", f"{form}", reference.double(left),
                  curve._to_affine(curve.point_double(form)))
        check("_to_jacobian", _fmt(left), left, curve._to_affine(curve._to_jacobian(left)))
        for right in candidates:
            expected = reference.add(left, right)
            inputs = f"{_fmt(left)} + {_fmt(right)}"
            check("point_add_affine", inputs, expected, curve.point_add_affine(left, right))
            for form_left in _jacobian_forms(left)[:2]:
                check("_point_add_mixed", inputs, expected,
                      curve._to_affine(curve._point_add_mixed(form_left, right)))
                for form_right in _jacobian_forms(right)[1:3]:
                    check("point_add(jacobian)", inputs, expected,
                          curve._to_affine(curve.point_add(form_left, form_right)))
    return mismatches


def diff_serialization(points: Sequence[tuple[int, int]] | None = None) -> list[Mismatch]:
    """Compare SEC1 and x-only encoding and decoding with the reference."""
    points = edge_points() if points is None else points
    mismatches = []

    def check(operation: str, inputs: str, expected: object, actual: object) -> None:
        if actual != expected:
            mismatches.append(Mismatch(operation, "keylab", inputs, _fmt(expected), _fmt(actual)))

    for point in points:
        compressed = reference.encode_compressed(point)
        uncompressed = reference.encode_uncompressed(point)
        check("compress_pubkey", _fmt(point), compressed, curve.compress_pubkey(point))
        check("serialize_sec1", _fmt(point), compressed, serialize_sec1(point))
        check("serialize_uncompressed", _fmt(point), uncompressed, serialize_uncompressed(point))
        check("serialize_xonly", _fmt(point), reference.encode_xonly(point), serialize_xonly(point))
        for encoded in (compressed, uncompressed):
            check("parse_sec1", encoded.hex(), reference.decode(encoded), parse_sec1(encoded))
        check("decompress_pubkey", compressed.hex(), reference.decode(compressed),
              curve.decompress_pubkey(compressed))
        check("lift_x", _fmt(point[0]), reference.decode(b"\x02" + point[0].to_bytes(32, "big")),
              curve.lift_x(point[0]))
    for invalid in (b"\x02" + bytes(32), b"\x04" + bytes(64), b"\x05" + bytes(32),
                    b"\x02" + curve.P.to_bytes(32, "big")):
        check("parse_sec1 rejects", invalid.hex(), _outcome(reference.decode, invalid),
              _outcome(parse_sec1, invalid))
    return mismatches


def diff_infinity(backends: Sequence[str] | None = None) -> list[Mismatch]:
    """Check point-at-infinity handling in every operation that can meet it."""
    backends = available_backends() if backends is None else backends
    g = curve.G
    minus_g = reference.negate(g)
    mismatches = []

    def check(operation: str, implementation: str, expected: object, actual: object) -> None:
        if actual != expected:
            mismatches.append(Mismatch(operation, implementation, "infinity case", _fmt(expected), _fmt(actual)))

    for backend in backends:
        for scalar in (0, curve.N, 2 * curve.N):
            check(f"scalar_mult({scalar:#x}, G)", backend, None, curve.scalar_mult(scalar, g, backend=backend))
        check("scalar_mult(k, None)", backend, None, curve.scalar_mult(5, None, backend=backend))
        check("scalar_mult(-1, G) rejects", backend, "raises ValueError",
              _outcome(curve.scalar_mult, -1, g, backend=backend))
    check("G + (-G)", "point_add_affine", None, curve.point_add_affine(g, minus_g))
    check("None + G", "point_add_affine", g, curve.point_add_affine(None, g))
    check("G + None", "point_add_affine", g, curve.point_add_affine(g, None))
    check("-None", "point_negate_affine", None, curve.point_negate_affine(None))
    check("_to_affine(infinity)", "jacobian", None, curve._to_affine(curve._INFINITY))
    check("double(infinity)", "jacobian", None, curve._to_affine(curve.point_double(curve._INFINITY)))
    check("G + (-G)", "jacobian", None,
          curve._to_affine(curve.point_add(curve._to_jacobian(g), curve._to_jacobian(minus_g))))
    check("is_on_curve(None)", "keylab", True, curve.is_on_curve(None))
    check("compress_pubkey(None) rejects", "keylab", "raises ValueError",
          _outcome(curve.compress_pubkey, None))
    check("serialize_sec1(None) rejects", "keylab", "raises ValueError",
          _outcome(serialize_sec1, None))
    return mismatches


def diff_batch_normalization(points: Sequence[Point] | None = None) -> list[Mismatch]:
    """Compare ``batch_to_affine`` with the reference, per point and as one batch.

    The batch mixes every edge point (and its negation) in several Jacobian forms
    with affine points and infinities, so positions, infinity handling, and the
    shared inversion are all exercised; sub-batches of sizes 0, 1, and 2 are
    checked as well.
    """
    base: list[Point] = list(edge_points()) if points is None else list(points)
    expected: list[Point] = []
    batch: list[object] = []
    for point in [*base, *(reference.negate(p) for p in base)]:
        for form in _jacobian_forms(point):
            batch.append(form)
            expected.append(point)
        batch.append(point)
        expected.append(point)
        batch.append(None)
        expected.append(None)
    batch.append((5, 7, curve.P))  # Z congruent to 0: infinity
    expected.append(None)
    mismatches = []
    for size in (0, 1, 2, len(batch)):
        actual = _outcome(curve.batch_to_affine, batch[:size])
        if actual != expected[:size]:
            mismatches.append(Mismatch("batch_to_affine", "keylab.ec.secp256k1", f"batch of {size}",
                                       f"{size} reference points", _fmt(actual)[:200]))
    one_by_one = [curve._to_affine(p) if isinstance(p, tuple) and len(p) == 3 else p for p in batch]
    if one_by_one != expected:
        mismatches.append(Mismatch("_to_affine", "keylab.ec.secp256k1", "per-point normalization",
                                   "reference points", "differs"))
    return mismatches


def validate_all(scalars: Iterable[int] | None = None) -> list[Mismatch]:
    """Run every differential check; the gate for any arithmetic change."""
    return [*diff_scalar_mult(scalars), *diff_group_operations(), *diff_serialization(),
            *diff_infinity(), *diff_batch_normalization()]


def assert_no_mismatches(mismatches: Sequence[Mismatch], *, limit: int = 10) -> None:
    """Raise ``AssertionError`` listing up to ``limit`` mismatches, if there are any."""
    if mismatches:
        shown = "\n".join(f"  {m}" for m in mismatches[:limit])
        more = f"\n  ... and {len(mismatches) - limit} more" if len(mismatches) > limit else ""
        raise AssertionError(f"{len(mismatches)} mismatch(es) against keylab.ec.reference:\n{shown}{more}")


__all__ = [
    "CONTRACT_BACKENDS",
    "EDGE_SCALARS",
    "NATIVE_BACKENDS",
    "PYTHON_STRATEGIES",
    "Mismatch",
    "assert_no_mismatches",
    "available_backends",
    "diff_batch_normalization",
    "diff_group_operations",
    "diff_infinity",
    "diff_scalar_mult",
    "diff_serialization",
    "edge_points",
    "hashed_point",
    "validate_all",
]
