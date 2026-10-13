"""Elementary number theory; primality congruences here are checks, not primality proofs."""

from __future__ import annotations


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return nonnegative gcd and Bezout coefficients x, y such that a*x + b*y == gcd."""
    old_r, remainder = a, b
    old_s, coefficient_s = 1, 0
    old_t, coefficient_t = 0, 1
    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_s, coefficient_s = coefficient_s, old_s - quotient * coefficient_s
        old_t, coefficient_t = coefficient_t, old_t - quotient * coefficient_t
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def totient(n: int) -> int:
    """Compute Euler's totient by trial division; intended for small research inputs."""
    if n < 1:
        raise ValueError("totient is defined here only for positive integers")
    result, remaining, factor = n, n, 2
    while factor * factor <= remaining:
        if remaining % factor == 0:
            while remaining % factor == 0:
                remaining //= factor
            result -= result // factor
        factor = 3 if factor == 2 else factor + 2
    if remaining > 1:
        result -= result // remaining
    return result


def fermat_check(base: int, modulus: int) -> bool:
    """Check a^(n-1) == 1 mod n for a coprime base; this is not a primality proof."""
    if modulus < 2:
        raise ValueError("modulus must be at least 2")
    if not 1 <= base < modulus:
        raise ValueError("base must be between 1 and modulus - 1")
    if extended_gcd(base, modulus)[0] != 1:
        return False
    return pow(base, modulus - 1, modulus) == 1


def euler_check(base: int, modulus: int) -> bool:
    """Check Euler's congruence using trial-division totient; not a primality proof."""
    if modulus < 2:
        raise ValueError("modulus must be at least 2")
    if not 1 <= base < modulus:
        raise ValueError("base must be between 1 and modulus - 1")
    if extended_gcd(base, modulus)[0] != 1:
        return False
    return pow(base, totient(modulus), modulus) == 1