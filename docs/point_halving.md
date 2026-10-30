# Point halving, doubling inversion, and division polynomials

Research modules: `keylab.ec.halving`, `keylab.ec.quartic`,
`keylab.ec.division_polynomials`. They are written to make the algebra
visible and testable, not for speed.

## Halving on secp256k1

The group order `N` is an odd prime, so doubling is a bijection and every
point `Q` has exactly one half `H` with `2H = Q`:

```
H = ((N + 1) / 2) · Q        because 2 · (N + 1)/2 ≡ 1 (mod N)
```

`halve_point(Q)` uses that identity; `halve_point_via_quartic(Q)` reaches the
same point by solving a polynomial, and the tests require both to agree.

### What halving does not do

If `Q = d·G`, then `H = (d · 2⁻¹ mod N)·G`. The discrete logarithm of `H` is
as unknown as `d`. Halving repeatedly (`halving_chain`), "walking back" from a
public key, or comparing halves of related keys yields points with unknown
discrete logarithms and gives **no information about `d`**. The tests make
this explicit: `halve(d·G) == (d · HALF_SCALAR mod N)·G`.

In the literature, point halving is a *speed* technique for elliptic curves
over binary fields (Knudsen 1999; Schroeppel), where solving the halving
equations can be cheaper than doubling. Over a prime field such as
secp256k1's, halving needs square roots and root-finding and is far slower
than doubling.

## The doubling quartic

For `y² = x³ + ax + b`, doubling gives

```
x(2P) = (x⁴ − 2a x² − 8b x + a²) / (4(x³ + ax + b))
```

so the x coordinates of every half of `Q` are roots of

```
x⁴ − 4x_Q x³ − 2a x² − (8b + 4a x_Q) x + (a² − 4b x_Q) = 0
```

which for secp256k1 (`a = 0`, `b = 7`) is `x⁴ − 4x_Q x³ − 56x − 28x_Q`.
`doubling_quartic` builds it, and the tests check that it equals
`φ₂ − x_Q·ψ₂²` from the division polynomials.

Over the algebraic closure the four roots are `x(H + T)` for the four
2-torsion points `T`. `invert_doubling_x` finds the roots in F_p
(`roots_mod_p`: `gcd(f, x^p − x)` then a deterministic Cantor–Zassenhaus
split) and classifies each:

- **on curve**: `x³ + 7` is a square, so `(x, ±y)` is in E(F_p). On secp256k1
  exactly one root is of this kind; one sign of y doubles to `Q`, the other
  to `−Q`.
- **twist**: `x³ + 7` is a non-square; the root is an x coordinate on the
  quadratic twist, not a curve point.

## Toy curves: when halves are not unique

On a curve whose group has full rational 2-torsion, doubling is 4-to-1 onto
`2E`, so a point has either 4 halves or none. The tests check this
exhaustively on small curves found by search:

| Curve | p mod 4 | #E | Points with 4 halves | Points with none |
|---|---|---:|---:|---:|
| `y² = x³ − x` over F₁₀₃ | 3 | 104 | 25 (+∞) | 78 |
| `y² = x³ − x` over F₁₁₃ | 1 | 128 | 31 (+∞) | 96 |
| `y² = x³ + 7` over F₁₀₀₉ | 1 | 1029 (odd) | — | every point has exactly 1 |

The F₁₁₃ curve exercises the Tonelli–Shanks square root (needed when
`p ≡ 1 mod 4`).

## Division polynomials

`division_polynomials(n)` returns the reduced polynomials `f_n` with
`ψ_n = f_n` for odd `n` and `ψ_n = 2y·f_n` for even `n`, using the standard
recurrences and `(2y)² = 4(x³ + ax + b)`. From them:

- `multiplication_by_n_x(n)` gives `x(nP) = φ_n / ψ_n²` with
  `φ_n = xψ_n² − ψ_{n+1}ψ_{n−1}`;
- `x_of_multiple(n, x)` evaluates it (returning `None` when `nP = ∞`).

Tests check degrees (`(n²−1)/2` odd, `(n²−4)/2` even), the closed form of
`ψ₃`, agreement with scalar multiplication on secp256k1 for `n = 1..8`, and
agreement with explicit repeated addition, including torsion, on toy curves.
