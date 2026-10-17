"""Elementary number theory; primality congruences here are checks, not primality proofs."""

from __future__ import annotations


def mod_inverse_builtin(a: int, modulus: int) -> int:
    """Return ``a**-1 mod modulus`` using Python's optimized modular inverse."""
    if type(a) is not int or type(modulus) is not int:
        raise TypeError("a and modulus must be integers")
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    try:
        return pow(a, -1, modulus)
    except ValueError as exc:
        raise ValueError("inverse does not exist: a and modulus are not coprime") from exc


def mod_inverse_egcd(a: int, modulus: int) -> int:
    """Return a modular inverse using the iterative Extended Euclidean Algorithm."""
    if type(a) is not int or type(modulus) is not int:
        raise TypeError("a and modulus must be integers")
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    old_r, remainder = a % modulus, modulus
    old_s, coefficient = 1, 0
    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_s, coefficient = coefficient, old_s - quotient * coefficient
    if old_r != 1:
        raise ValueError(f"inverse does not exist: gcd(a, modulus) = {old_r}")
    return old_s % modulus


def mod_inverse_fermat(a: int, prime_modulus: int) -> int:
    """Compute an inverse with Fermat's theorem; caller must supply a prime modulus."""
    if type(a) is not int or type(prime_modulus) is not int:
        raise TypeError("a and prime_modulus must be integers")
    if prime_modulus <= 1:
        raise ValueError("prime_modulus must be greater than 1")
    reduced = a % prime_modulus
    if reduced == 0:
        raise ValueError("zero has no modular inverse")
    inverse = pow(reduced, prime_modulus - 2, prime_modulus)
    if reduced * inverse % prime_modulus != 1:
        raise ValueError("Fermat method failed; prime_modulus must be prime")
    return inverse


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


__all__ = [
    "euler_check",
    "extended_gcd",
    "fermat_check",
    "mod_inverse_builtin",
    "mod_inverse_egcd",
    "mod_inverse_fermat",
    "totient",
]
