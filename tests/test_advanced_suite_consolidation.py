"""advanced_suite's curve arithmetic is a thin layer over keylab.ec (M2.3).

Three kinds of test:

- **Regression:** every wrapper reproduces its pre-consolidation output exactly.
  `_snapshot()` regenerates the same 2,600+ seeded calls captured before the
  change; their outputs must hash to the digests recorded then.
- **No duplicate arithmetic:** the wrappers must call keylab.ec (spy tests),
  and the module source must not contain field formulas again (AST guard).
- **Validation framework:** wrapper results agree with keylab.ec.reference and
  every contract backend.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import random
from functools import cache

import pytest

from keylab import advanced_suite as a
from keylab.ec import reference as ref
from keylab.ec import secp256k1 as curve
from keylab.ec import validation

P, N, G = curve.P, curve.N, curve.G

# SHA-256 (first 128 bits) of each function's outputs from _snapshot(), recorded on the
# pre-consolidation code (v0.3.0.dev0 at 9a143ce). A mismatch means a wrapper changed behaviour.
PRE_CONSOLIDATION_DIGESTS = {
    "jacobian_double": "72d693ce0b4fb5495be7650669dc3976",
    "jacobian_add": "d2129951ece641e9c9b714c01450e7a9",
    "jacobian_add_mixed": "8a8e754945f87384f787c09a1ab8e249",
    "jacobian_to_affine": "c9837e2e2aa05162e57600385f319301",
    "batch_jacobian_to_affine": "82322b1c4ce0c4d797ae82d886bd050e",
    "batch_inv": "c4aa35d2a1afa57068c2355ee66bea6d",
    "field_inv": "a92aa296c0d1d933bd5edd1f51ce6db2",
    "scalar_inv": "92feed1dddfdeb9b293aec4254ef50c1",
    "eea_mod_inv": "89fe97a026b346124d36f43ea44f0f4c",
    "point_negate": "2537b4bc602ec2ee3c23f30ba1357d05",
    "compute_naf": "5b69532e65033d5f01642d965e7ce156",
    "scalar_mult_naf_jacobian": "26fbf8fb134aa9d3fdf82e01ae0ab10e",
    "scalar_mult_naf": "d9c52d477a02591304e84a6b06d81d7d",
    "scalar_mult_g_fast": "97897c14bbebb5822b3fc8ff6c3ec163",
    "scalar_multiplication_trace": "624ea1a49dd24678a12cc685f8f1a34d",
    "curve_add_geometry": "adf3124c54c623d31889b9de6de73c0e",
    "hash_to_curve": "fb93adc25e8269cae2132c8fdbf88255",
    "advance_public_key": "34481d9694ccaffa8915f66de41a0bc3",
    "rfc6979_trace": "82e7a9c2cce8cc75802379348f17b371",
    "compress_pubkey": "9ffcc8fb592fda9001b28fad78f03b74",
    "constants": "006ba7474bbb4290dc3c6f81dedc2f10",
}


def _call(fn, *args):
    try:
        out = fn(*args)
        return out.hex() if isinstance(out, (bytes, bytearray)) else out
    except (ValueError, TypeError) as exc:  # errors are part of the recorded behaviour
        return f"!{type(exc).__name__}: {exc}"


@cache
def _snapshot() -> dict[str, list]:
    """Regenerate the seeded calls recorded before consolidation (do not change the order)."""
    rng = random.Random(2023)
    pts = [G, a.point_negate(G)] + [a.scalar_mult_naf(rng.randrange(1, N), G) for _ in range(12)]

    def jac(p, z):
        return (p[0] * z * z % P, p[1] * z**3 % P, z)

    J = [(0, 0, 0)] + [jac(p, rng.choice([1, 2, rng.randrange(1, P)])) for p in pts]
    out: dict[str, list] = {}
    out["jacobian_double"] = [_call(a.jacobian_double, j) for j in J + [(5, 0, 3), (1, 1, 0)]]
    out["jacobian_add"] = [_call(a.jacobian_add, x, y) for x in J for y in J[:6]] + [
        _call(a.jacobian_add, (0, 0, 0), (P + 5, P + 7, 1)), _call(a.jacobian_add, (P + 5, P + 7, 1), (0, 0, 0)),
        _call(a.jacobian_add, J[1], jac(G, 9)), _call(a.jacobian_add, J[1], jac(a.point_negate(G), 4))]
    out["jacobian_add_mixed"] = [_call(a.jacobian_add_mixed, x, p) for x in J for p in pts[:5] + [(0, 0)]] + [
        _call(a.jacobian_add_mixed, (0, 0, 0), (0, 0)), _call(a.jacobian_add_mixed, jac(G, 3), a.point_negate(G))]
    out["jacobian_to_affine"] = [_call(a.jacobian_to_affine, j) for j in J + [(1, 2, 0), (1, 2, P), (3, 4, 2 * P)]]
    out["batch_jacobian_to_affine"] = [_call(a.batch_jacobian_to_affine, J), _call(a.batch_jacobian_to_affine, []),
                                       _call(a.batch_jacobian_to_affine, [(1, 2, 0), (1, 2, P), J[3]])]
    vals = [rng.randrange(0, P) for _ in range(30)] + [0, P, 2 * P, -3, 1]
    out["batch_inv"] = [_call(a.batch_inv, vals), _call(a.batch_inv, []), _call(a.batch_inv, [1, 2, 4, 7, 8], 15),
                        _call(a.batch_inv, [3, 5], 15), _call(a.batch_inv, [1, 2.5]), _call(a.batch_inv, [1], 1),
                        _call(a.batch_inv, [0, 0]), _call(a.batch_inv, [N - 1, 5], N)]
    out["field_inv"] = [_call(a.field_inv, v) for v in (1, 2, P - 1, 0, P, 12345)]
    out["scalar_inv"] = [_call(a.scalar_inv, v) for v in (1, 2, N - 1, 0, 12345)]
    out["eea_mod_inv"] = [_call(a.eea_mod_inv, v) for v in (1, 2, P - 1, 0, 12345)]
    out["point_negate"] = [_call(a.point_negate, p) for p in pts + [(0, 0), (5, 0)]]
    out["compute_naf"] = [_call(a.compute_naf, k)
                          for k in list(range(2001)) + [N - 1, 2**256 - 1, 2**300 + 7, -1]]
    ks = ([0, 1, 2, 3, 15, 16, N - 1, N, N + 1, 2 * N + 3, -1, -5, -(N - 1), 2**255, 2**300 + 9]
          + [rng.randrange(1, N) for _ in range(15)])
    out["scalar_mult_naf_jacobian"] = [_call(a.scalar_mult_naf_jacobian, k, p) for k in ks for p in pts[:4]]
    out["scalar_mult_naf"] = [_call(a.scalar_mult_naf, k, p) for k in ks for p in pts[:4]]
    out["scalar_mult_g_fast"] = [_call(a.scalar_mult_g_fast, k) for k in ks]
    out["scalar_multiplication_trace"] = [
        _call(a.scalar_multiplication_trace, k, p)
        for k in [0, 1, 2, 5, 255, N - 1, N + 3, 2**70 + 5] for p in pts[:3]
    ] + [_call(a.scalar_multiplication_trace, -1), _call(a.scalar_multiplication_trace, 3, (1, 2))]
    out["curve_add_geometry"] = [_call(a.curve_add_geometry, x, y)
                                 for x in pts[:5] + [(0, 0)] for y in pts[:5] + [(0, 0)]] + [
        _call(a.curve_add_geometry, (1, 2), G)]
    out["hash_to_curve"] = [_call(a.hash_to_curve_try_and_increment, s)
                            for s in ["", "a", "keylab", "test-vector", "x" * 100] + [f"seed{i}" for i in range(40)]]
    out["advance_public_key"] = [
        _call(a.advance_public_key, a.compress_pubkey(G).hex(), 5),
        _call(a.advance_public_key, a.compress_pubkey(pts[3]).hex(), 50),
        _call(a.advance_public_key, a.compress_pubkey(a.point_negate(G)).hex(), 3),
        _call(a.advance_public_key, "02" + "00" * 32, 2)]
    out["rfc6979_trace"] = [_call(a.rfc6979_trace, d, m) for d in (1, 12345, N - 1) for m in ("", "hello")]
    out["compress_pubkey"] = [_call(a.compress_pubkey, p) for p in pts + [(0, 0), (5, 7)]]
    out["constants"] = [P, N, list(G)]
    return out


def _digest(values: list) -> str:
    canonical = json.dumps(json.loads(json.dumps(values, default=list)), separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


# --- regression: identical to the pre-consolidation behaviour --------------------------------------

@pytest.mark.parametrize("function", sorted(PRE_CONSOLIDATION_DIGESTS))
def test_wrapper_reproduces_pre_consolidation_outputs(function: str) -> None:
    assert _digest(_snapshot()[function]) == PRE_CONSOLIDATION_DIGESTS[function], function


def test_regression_snapshot_covers_every_wrapper() -> None:
    assert set(_snapshot()) == set(PRE_CONSOLIDATION_DIGESTS)
    assert sum(len(v) for v in _snapshot().values()) > 2600


# --- the wrappers delegate to keylab.ec -------------------------------------------------------------

DELEGATIONS = [
    ("point_add", lambda: a.jacobian_add((G[0], G[1], 1), (G[0], P - G[1], 1))),
    ("point_double", lambda: a.jacobian_double((G[0], G[1], 1))),
    ("_point_add_mixed", lambda: a.jacobian_add_mixed((G[0], G[1], 2), G)),
    ("_to_affine", lambda: a.jacobian_to_affine((G[0], G[1], 1))),
    ("batch_inverse", lambda: a.batch_inv([1, 2, 3])),
    ("batch_to_affine", lambda: a.batch_jacobian_to_affine([(G[0], G[1], 1)])),
    ("wnaf_digits", lambda: a.compute_naf(12345)),
    ("_scalar_mult_generator_affine_window", lambda: a.scalar_mult_g_fast(12345)),
    ("_generator_affine_window_table", lambda: a._init_g_precomp_table()),
    ("point_add_geometry", lambda: a.curve_add_geometry(G, G)),
    ("sqrt_mod_p", lambda: a.hash_to_curve_try_and_increment("keylab")),
]


@pytest.mark.parametrize("core_name,call", DELEGATIONS, ids=[name for name, _ in DELEGATIONS])
def test_wrapper_delegates_to_keylab_ec(monkeypatch, core_name: str, call) -> None:
    real = getattr(curve, core_name)
    calls: list[int] = []

    def spy(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(curve, core_name, spy)
    call()
    assert calls, f"advanced_suite no longer calls keylab.ec.secp256k1.{core_name}"


def test_curve_constants_are_the_shared_ones() -> None:
    assert a.SECP256K1_P is curve.P and a.SECP256K1_N is curve.N and a.SECP256K1_G is curve.G


# Functions allowed to do arithmetic modulo p themselves, and why.
ARITHMETIC_ALLOWLIST = {
    "jacobian_double": "Z3 = 2*Y*Z for a non-canonical infinity input, to keep the old raw output",
    "run_performance_benchmark": "times individual Fermat inversions against batch inversion",
}


def _module_tree() -> ast.Module:
    return ast.parse(inspect.getsource(a))


def _is_p(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "SECP256K1_P"


def test_no_field_multiplication_formulas_outside_the_allowlist() -> None:
    offenders = []
    for function in ast.walk(_module_tree()):
        if not isinstance(function, ast.FunctionDef) or function.name in ARITHMETIC_ALLOWLIST:
            continue
        for node in ast.walk(function):
            # `<product> % SECP256K1_P`: a field multiplication, i.e. a curve formula.
            if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_p(node.right)
                    and any(isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Mult, ast.Pow))
                            for sub in ast.walk(node.left))):
                offenders.append(f"{function.name}:{node.lineno}")
    assert offenders == [], f"duplicated field arithmetic reappeared in advanced_suite: {offenders}"


def test_no_square_roots_or_inversions_by_exponentiation_outside_the_allowlist() -> None:
    offenders = []
    for function in ast.walk(_module_tree()):
        if not isinstance(function, ast.FunctionDef) or function.name in ARITHMETIC_ALLOWLIST:
            continue
        for node in ast.walk(function):
            # pow(x, e, SECP256K1_P) with a non-literal exponent: sqrt, Euler test, or Fermat inverse.
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "pow"
                    and len(node.args) == 3 and _is_p(node.args[2])
                    and not isinstance(node.args[1], ast.Constant)):
                offenders.append(f"{function.name}:{node.lineno}")
    assert offenders == [], f"square root / inversion by exponentiation reappeared: {offenders}"


def test_removed_duplicate_table_is_gone() -> None:
    assert not hasattr(a, "_G_PRECOMP_AFFINE")


# --- the validation framework: wrappers agree with the reference and every backend -----------------

def _ref(point):
    return (0, 0) if point is None else point


@pytest.mark.parametrize("scalar", [0, 1, 2, 3, 16, N - 1, N, N + 1, 2 * N + 1,
                                    curve.LAMBDA, N - curve.LAMBDA, 2**128, 2**256 - 1])
def test_naf_multiplication_matches_reference_and_contract_backends(scalar: int) -> None:
    for point in validation.edge_points()[:4]:
        expected = ref.scalar_mult(scalar, point)
        assert a.scalar_mult_naf(scalar, point) == _ref(expected)
        assert a.jacobian_to_affine(a.scalar_mult_naf_jacobian(scalar, point)) == _ref(expected)
        assert a.scalar_mult_naf(-scalar, point) == _ref(ref.negate(expected))
        for backend in validation.available_backends(include_strategies=False):
            assert _ref(curve.scalar_mult(scalar, point, backend=backend)) == _ref(expected)
    assert a.scalar_mult_g_fast(scalar) == _ref(ref.scalar_mult(scalar))


def test_jacobian_wrappers_match_reference_on_edge_points() -> None:
    points = list(validation.edge_points())
    for left in points:
        for right in points[:4]:
            for z1 in (1, 3, P - 2):
                jl = (left[0] * z1 * z1 % P, left[1] * z1**3 % P, z1)
                jr = (right[0] * 4 % P, right[1] * 8 % P, 2)
                assert a.jacobian_to_affine(a.jacobian_add(jl, jr)) == _ref(ref.add(left, right))
                assert a.jacobian_to_affine(a.jacobian_add_mixed(jl, right)) == _ref(ref.add(left, right))
                assert a.jacobian_to_affine(a.jacobian_double(jl)) == _ref(ref.double(left))
        assert a.point_negate(left) == ref.negate(left)


def test_batch_wrappers_match_reference_and_keep_zero_compatibility() -> None:
    points = list(validation.edge_points())
    batch = [(p[0] * 9 % P, p[1] * 27 % P, 3) for p in points] + [(1, 2, 0), (1, 2, P)]
    assert a.batch_jacobian_to_affine(batch) == points + [(0, 0), (0, 0)]
    assert a.batch_inv([0, 5, 0, P - 1]) == [0, pow(5, -1, P), 0, P - 1]
    with pytest.raises(ValueError, match="must be integers"):
        a.batch_inv([1, "2"])
    with pytest.raises(ValueError, match="modulus must be"):
        a.batch_inv([1], 0)


def test_naf_digits_reconstruct_the_scalar_and_are_non_adjacent() -> None:
    rng = random.Random(9)
    for k in [0, 1, 7, N - 1, 2**300 + 1] + [rng.getrandbits(256) for _ in range(50)]:
        digits = a.compute_naf(k)
        assert sum(d << i for i, d in enumerate(digits)) == k
        assert all(d in (-1, 0, 1) for d in digits)
        assert all(not (digits[i] and digits[i + 1]) for i in range(len(digits) - 1))


def test_compatibility_edge_paths() -> None:
    # (0, 0) is this suite's affine infinity; negating it must keep working.
    assert a.point_negate((0, 0)) == (0, 0)
    # A non-canonical Jacobian infinity keeps its previous raw doubling output.
    assert a.jacobian_double((1, 1, 0)) == (1, 1, 0)
    assert a.jacobian_double((G[0], 0, 5)) == (0, 0, 0)
    # Z congruent to 0 but not 0: still an error, as before.
    with pytest.raises(ValueError):
        a.jacobian_to_affine((1, 2, P))
    # P + (-P) in each wrapper uses the suite's (0, 0, 0) / (0, 0) convention.
    jg = (G[0], G[1], 1)
    assert a.jacobian_add(jg, (G[0], P - G[1], 1)) == (0, 0, 0)
    assert a.jacobian_add_mixed(jg, (G[0], P - G[1])) == (0, 0, 0)
    assert a.curve_add_geometry(G, (G[0], P - G[1])) == {
        "slope": None, "third_intersection": (0, 0), "sum": (0, 0)}
