"""SAT encoding of the bounded-range ECDLP: find k in [L, U] with k*G == Q.

Mathematical role: encode the double-and-add scalar multiplication over a prime
field as a boolean satisfiability instance, so an off-the-shelf SAT solver
searches for the scalar ``k`` in a *declared, bounded* range ``[L, U]``. ``k - L``
is a fixed-width bit vector with an upper-bound comparator (cheap); the cost is
dominated by encoding full-width modular field arithmetic for each point
operation, which grows with the number of doubling steps regardless of how
narrow ``[L, U]`` is.

Scope boundary: the range ``[L, U]`` is required and validated on every public
entry point; this never attempts unbounded/full secp256k1 ECDLP (the field
encoding makes even a few doublings intractable -- that ceiling is the measured
result, see scripts/benchmark_sat_ecdlp.py and SEC_STATE_JOURNAL.md). It is a
distinct *method* for the same bounded-range problem as kangaroo/BSGS, built by
extending KeyLab's existing CNF exporter (:mod:`keylab.sat.cnf`), not a new one.

The affine addition law here is the *incomplete* one (it assumes the running
accumulator never shares an x-coordinate with the constant point being added);
test instances are constructed to avoid that exceptional case.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.sat.cnf import CNF

__all__ = ["BoundedECDLPInstance", "SATEncodingStats", "encode_bounded_ecdlp"]

Bits = tuple[int, ...]  # LSB-first literals
CurvePoint = tuple[int, int]  # affine (x, y) over F_p


# --- arbitrary-width helpers over the existing CNF exporter --------------------------------------

def _const(cnf: CNF, value: int, width: int) -> Bits:
    return tuple(cnf.constant(bool((value >> i) & 1)) for i in range(width))


def _add(cnf: CNF, a: Bits, b: Bits) -> Bits:
    """Ripple-carry add of two LSB-first bit vectors; result is max(len)+1 bits."""
    n = max(len(a), len(b))
    zero = cnf.constant(False)
    out: list[int] = []
    carry = zero
    for i in range(n):
        ai = a[i] if i < len(a) else zero
        bi = b[i] if i < len(b) else zero
        s, carry = cnf.full_adder(ai, bi, carry)
        out.append(s)
    out.append(carry)
    return tuple(out)


def _mul(cnf: CNF, a: Bits, b: Bits) -> Bits:
    """Schoolbook multiply of two LSB-first bit vectors; result is len(a)+len(b) bits."""
    width = len(a) + len(b)
    zero = cnf.constant(False)
    acc: Bits = tuple(zero for _ in range(width))
    for j, bj in enumerate(b):
        partial = tuple(zero for _ in range(j)) + tuple(cnf.and_gate(ai, bj) for ai in a)
        acc = _add(cnf, acc, partial)[:width]
    return acc[:width]


def _mul_by_constant(cnf: CNF, a: Bits, constant: int) -> Bits:
    """Multiply a variable bit vector by a constant (shifts + adds; no AND gates)."""
    zero = cnf.constant(False)
    terms = [tuple(zero for _ in range(i)) + a for i in range(constant.bit_length()) if (constant >> i) & 1]
    if not terms:
        return (zero,)
    acc = terms[0]
    for term in terms[1:]:
        acc = _add(cnf, acc, term)
    return acc


def _assert_equal(cnf: CNF, a: Bits, b: Bits) -> None:
    zero = cnf.constant(False)
    for i in range(max(len(a), len(b))):
        ai = a[i] if i < len(a) else zero
        bi = b[i] if i < len(b) else zero
        cnf.add_clause(ai, -bi)
        cnf.add_clause(-ai, bi)


def _assert_equal_if(cnf: CNF, cond: int, a: Bits, b: Bits) -> None:
    """Assert ``cond -> (a == b)``; when ``cond`` is false the bits are unconstrained."""
    zero = cnf.constant(False)
    for i in range(max(len(a), len(b))):
        ai = a[i] if i < len(a) else zero
        bi = b[i] if i < len(b) else zero
        cnf.add_clause(-cond, ai, -bi)
        cnf.add_clause(-cond, -ai, bi)


def _assert_leq_constant(cnf: CNF, a: Bits, bound: int) -> None:
    """Assert int(a) <= bound by introducing slack s >= 0 with a + s == bound."""
    width = len(a)
    slack = tuple(cnf.fresh_var() for _ in range(width))
    _assert_equal(cnf, _add(cnf, a, slack), _const(cnf, bound, width + 1))


def _mod_mul(cnf: CNF, a: Bits, b: Bits, p: int, width: int) -> Bits:
    """Return c (width bits) with c == a*b mod p, via a*b == q*p + c, c < p."""
    product = _mul(cnf, a, b)
    quotient = tuple(cnf.fresh_var() for _ in range(width))
    remainder = tuple(cnf.fresh_var() for _ in range(width))
    _assert_equal(cnf, product, _add(cnf, _mul_by_constant(cnf, quotient, p), remainder))
    _assert_leq_constant(cnf, remainder, p - 1)
    return remainder


def _mod_sub(cnf: CNF, a: Bits, b: Bits, p: int, width: int) -> Bits:
    """Return c (width bits) with c == (a - b) mod p, via b + c == a + m*p, m in {0,1}."""
    remainder = tuple(cnf.fresh_var() for _ in range(width))
    _assert_leq_constant(cnf, remainder, p - 1)
    m = cnf.fresh_var()
    mp = tuple(cnf.and_gate(m, cnf.constant(bool((p >> i) & 1))) for i in range(width))
    _assert_equal(cnf, _add(cnf, b, remainder), _add(cnf, a, mp))
    return remainder


def _point_add_constant(
    cnf: CNF, cond: int, x1: Bits, y1: Bits, x2: int, y2: int, p: int, width: int
) -> tuple[Bits, Bits]:
    """Encode (x1,y1) + (x2,y2) with (x2,y2) a constant point (incomplete addition law).

    The sole unsatisfiable-when-exceptional constraint (``inv*dx == 1``, which has
    no solution when ``dx == 0``) is gated on ``cond``: when this add is discarded
    (``cond`` false, i.e. the scalar bit is 0) it imposes nothing, so an exceptional
    *discarded* add cannot make the whole instance UNSAT.
    """
    x2b, y2b = _const(cnf, x2, width), _const(cnf, y2, width)
    dx = _mod_sub(cnf, x1, x2b, p, width)
    dy = _mod_sub(cnf, y1, y2b, p, width)
    inverse = tuple(cnf.fresh_var() for _ in range(width))
    _assert_leq_constant(cnf, inverse, p - 1)
    _assert_equal_if(cnf, cond, _mod_mul(cnf, inverse, dx, p, width), _const(cnf, 1, width))
    lam = _mod_mul(cnf, dy, inverse, p, width)
    lam2 = _mod_mul(cnf, lam, lam, p, width)
    x3 = _mod_sub(cnf, _mod_sub(cnf, lam2, x1, p, width), x2b, p, width)  # lam^2 - x1 - x2
    y3 = _mod_sub(cnf, _mod_mul(cnf, lam, _mod_sub(cnf, x1, x3, p, width), p, width), y1, p, width)
    return x3, y3


@dataclass
class SATEncodingStats:
    steps: int
    variable_count: int
    clause_count: int


@dataclass
class BoundedECDLPInstance:
    """A built CNF for k in [L, U] with k*G == Q, plus the bits to recover k."""

    formula: CNF
    difference_bits: Bits  # d = k - L, LSB-first
    lower: int
    steps: int

    @property
    def stats(self) -> SATEncodingStats:
        return SATEncodingStats(self.steps, self.formula.variable_count, len(self.formula.clauses))

    def to_dimacs(self) -> str:
        return self.formula.to_dimacs()

    def recover_k(self, assignments: dict[int, bool]) -> int:
        d = 0
        for i, literal in enumerate(self.difference_bits):
            if abs(literal) in assignments and assignments[abs(literal)] == (literal > 0):
                d |= 1 << i
        return self.lower + d


def encode_bounded_ecdlp(
    *,
    p: int,
    width: int,
    base_point: CurvePoint,
    doubling_points: list[CurvePoint],
    target: CurvePoint,
    lower: int,
    upper: int,
    cnf: CNF | None = None,
) -> BoundedECDLPInstance:
    """Encode ``k*G == target`` for ``k in [lower, upper]`` as CNF.

    ``base_point`` is ``lower*G``; ``doubling_points[i]`` is ``2**i * G``; ``target``
    is ``Q``. ``steps = len(doubling_points)`` is the number of point-doubling
    positions (the scale knob). The range is required and validated. A ``cnf`` may
    be injected (e.g. a streaming subclass that writes clauses to disk) to bound
    the encoder's memory; a fresh :class:`~keylab.sat.cnf.CNF` is used otherwise.
    """
    if type(lower) is not int or type(upper) is not int:
        raise TypeError("lower and upper must be integers")
    if not 0 <= lower <= upper:
        raise ValueError("require 0 <= lower <= upper (a bounded range is mandatory)")
    span = upper - lower
    steps = len(doubling_points)
    if steps < 1 or span >= (1 << steps):
        raise ValueError("doubling_points must cover the range: need span < 2**len(doubling_points)")

    if cnf is None:
        cnf = CNF()
    difference_bits = tuple(cnf.fresh_var() for _ in range(steps))
    _assert_leq_constant(cnf, difference_bits, span)  # d <= upper - lower

    acc_x, acc_y = _const(cnf, base_point[0], width), _const(cnf, base_point[1], width)
    for i in range(steps):
        added_x, added_y = _point_add_constant(
            cnf, difference_bits[i], acc_x, acc_y, *doubling_points[i], p, width
        )
        acc_x = tuple(cnf.mux(difference_bits[i], t, f) for t, f in zip(added_x, acc_x))
        acc_y = tuple(cnf.mux(difference_bits[i], t, f) for t, f in zip(added_y, acc_y))

    _assert_equal(cnf, acc_x, _const(cnf, target[0], width))
    _assert_equal(cnf, acc_y, _const(cnf, target[1], width))
    return BoundedECDLPInstance(formula=cnf, difference_bits=difference_bits, lower=lower, steps=steps)
