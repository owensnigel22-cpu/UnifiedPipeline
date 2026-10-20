"""Educational RSA public-key checks for known weak key constructions."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from math import gcd, isqrt
from random import Random, SystemRandom

from keylab.backends import integer_nth_root, modular_pow
from keylab.numtheory.core import mod_inverse_builtin

_UINT64_LIMIT = 1 << 64
_MILLER_RABIN_BASES_64 = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


@dataclass(frozen=True)
class WienerRecovery:
    """RSA private exponent and prime factors recovered by Wiener's attack."""

    private_exponent: int
    p: int
    q: int


@dataclass(frozen=True)
class RSAExponentiationResult:
    """Raw textbook-RSA exponentiation results for an educational round trip."""

    message: int
    ciphertext: int
    recovered_message: int

    @property
    def success(self) -> bool:
        """Whether private exponentiation recovered the original integer."""
        return self.recovered_message == self.message


@dataclass(frozen=True)
class SharedFactorFinding:
    """A nontrivial common divisor found between two RSA moduli."""

    first_index: int
    second_index: int
    common_divisor: int


@dataclass(frozen=True)
class PollardRhoResult:
    """Result and work counters from bounded Pollard–Brent factor search."""

    factor: int | None
    cofactor: int | None
    iterations: int
    attempts: int

    @property
    def success(self) -> bool:
        """Whether a proper factor pair was found."""
        return self.factor is not None and self.cofactor is not None


def rsa_exponentiation_roundtrip(
    message: int,
    modulus: int,
    public_exponent: int,
    private_exponent: int,
) -> RSAExponentiationResult:
    """Apply raw RSA public/private modular exponentiation and report success.

    This is an educational arithmetic demonstration only: it applies no
    encoding or padding and is not suitable for protecting real messages.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    if public_exponent <= 0 or private_exponent <= 0:
        raise ValueError("RSA exponents must be positive")
    if not 0 <= message < modulus:
        raise ValueError("message must be between 0 and modulus - 1")

    ciphertext = modular_pow(message, public_exponent, modulus)
    recovered_message = modular_pow(ciphertext, private_exponent, modulus)
    return RSAExponentiationResult(message, ciphertext, recovered_message)


def batch_gcd(moduli: Iterable[int]) -> tuple[SharedFactorFinding, ...]:
    """Report pairwise common divisors among RSA moduli.

    This diagnostic uses pairwise GCDs and does not perform general RSA
    factorization. A finding equal to either modulus can indicate duplicate
    moduli rather than a proper factor.
    """
    values = tuple(moduli)
    if any(type(modulus) is not int or modulus <= 1 for modulus in values):
        raise ValueError("every modulus must be an integer greater than 1")

    findings = []
    for first_index, first in enumerate(values):
        for second_index in range(first_index + 1, len(values)):
            common_divisor = gcd(first, values[second_index])
            if common_divisor > 1:
                findings.append(
                    SharedFactorFinding(first_index, second_index, common_divisor)
                )
    return tuple(findings)


def pollard_rho_factor(
    modulus: int,
    *,
    max_iterations: int = 1_000_000,
    batch_size: int = 128,
    max_attempts: int = 16,
    seed: int | None = None,
) -> PollardRhoResult:
    """Find a nontrivial factor with bounded Pollard–Brent rho iterations.

    Brent's cycle schedule batches several differences into one GCD, with a
    single-step fallback when a batch collapses to the whole modulus. A fixed
    ``seed`` makes toy experiments reproducible; otherwise a system-seeded
    generator selects fresh polynomials. This probabilistic method is useful
    for small/research semiprimes, not standard-size RSA moduli.
    """
    if type(modulus) is not int or modulus <= 1:
        raise ValueError("modulus must be an integer greater than 1")
    if type(max_iterations) is not int or max_iterations < 0:
        raise ValueError("max_iterations must be a nonnegative integer")
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if seed is not None and (type(seed) is not int or seed < 0):
        raise ValueError("seed must be a nonnegative integer or None")

    if modulus == 2:
        return PollardRhoResult(None, None, 0, 0)
    if modulus % 2 == 0:
        return PollardRhoResult(2, modulus // 2, 0, 0)
    for small_prime in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if modulus % small_prime == 0:
            if modulus == small_prime:
                return PollardRhoResult(None, None, 0, 0)
            return PollardRhoResult(small_prime, modulus // small_prime, 0, 0)

    rng = Random(seed) if seed is not None else SystemRandom()
    total_iterations = 0
    attempts = 0
    while total_iterations < max_iterations and attempts < max_attempts:
        attempts += 1
        y = rng.randrange(1, modulus)
        constant = rng.randrange(1, modulus)
        factor = 1
        cycle_length = 1
        x = 0
        saved_y = 0

        while factor == 1 and total_iterations < max_iterations:
            x = y
            advance = min(cycle_length, max_iterations - total_iterations)
            for _ in range(advance):
                y = (y * y + constant) % modulus
            total_iterations += advance
            if advance < cycle_length:
                break

            offset = 0
            while offset < cycle_length and factor == 1 and total_iterations < max_iterations:
                saved_y = y
                block_size = min(batch_size, cycle_length - offset, max_iterations - total_iterations)
                product = 1
                for _ in range(block_size):
                    y = (y * y + constant) % modulus
                    product = product * abs(x - y) % modulus
                total_iterations += block_size
                factor = gcd(product, modulus)
                offset += block_size
            cycle_length <<= 1

        if factor == modulus:
            factor = 1
            while factor == 1 and total_iterations < max_iterations:
                saved_y = (saved_y * saved_y + constant) % modulus
                total_iterations += 1
                factor = gcd(abs(x - saved_y), modulus)

        if 1 < factor < modulus:
            first, second = sorted((factor, modulus // factor))
            if first * second == modulus:
                return PollardRhoResult(first, second, total_iterations, attempts)

    return PollardRhoResult(None, None, total_iterations, attempts)


def _integer_nth_root(value: int, exponent: int) -> int | None:
    """Return the exact nonnegative integer root, or None when it is not exact."""
    root, exact = integer_nth_root(value, exponent)
    return root if exact else None


def hastad_broadcast(
    ciphertexts: Iterable[int],
    moduli: Iterable[int],
    public_exponent: int,
) -> int:
    """Recover a repeated unpadded message from a toy RSA broadcast.

    Requires at least ``public_exponent`` ciphertexts of the same integer
    message, pairwise-coprime moduli, and an exact integer root after CRT.
    This is not applicable to properly randomized/padded RSA ciphertexts.
    """
    cipher_values = tuple(ciphertexts)
    modulus_values = tuple(moduli)
    if type(public_exponent) is not int or public_exponent < 2:
        raise ValueError("public_exponent must be an integer of at least 2")
    if len(cipher_values) != len(modulus_values):
        raise ValueError("ciphertexts and moduli must have the same length")
    if len(modulus_values) < public_exponent:
        raise ValueError("at least public_exponent ciphertexts and moduli are required")
    if any(type(modulus) is not int or modulus <= 1 for modulus in modulus_values):
        raise ValueError("every modulus must be an integer greater than 1")
    if any(type(ciphertext) is not int for ciphertext in cipher_values):
        raise ValueError("every ciphertext must be an integer")
    if any(not 0 <= ciphertext < modulus for ciphertext, modulus in zip(cipher_values, modulus_values)):
        raise ValueError("each ciphertext must be between 0 and its modulus - 1")

    for index, modulus in enumerate(modulus_values):
        if any(gcd(modulus, other) != 1 for other in modulus_values[:index]):
            raise ValueError("moduli must be pairwise coprime")

    combined_modulus = 1
    for modulus in modulus_values:
        combined_modulus *= modulus
    combined_ciphertext = 0
    for ciphertext, modulus in zip(cipher_values, modulus_values):
        partial_modulus = combined_modulus // modulus
        inverse = mod_inverse_builtin(partial_modulus, modulus)
        combined_ciphertext += ciphertext * partial_modulus * inverse
    combined_ciphertext %= combined_modulus

    message = _integer_nth_root(combined_ciphertext, public_exponent)
    if message is None or any(
        modular_pow(message, public_exponent, modulus) != ciphertext
        for ciphertext, modulus in zip(cipher_values, modulus_values)
    ):
        raise ValueError("CRT result is not an exact, verified integer power")
    return message


def fermat_factor(
    modulus: int,
    max_iterations: int = 1_000_000,
) -> tuple[int | None, int | None, int]:
    """Find a nontrivial factor pair when an odd modulus has close factors.

    Fermat factorization is bounded and is not a general-purpose factoring
    algorithm. The returned factors are not guaranteed to be prime.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    if max_iterations < 0:
        raise ValueError("max_iterations must be nonnegative")
    if modulus == 2:
        return None, None, 0
    if modulus % 2 == 0:
        return 2, modulus // 2, 1

    a = isqrt(modulus)
    if a * a < modulus:
        a += 1
    difference = a * a - modulus

    for iterations in range(1, max_iterations + 1):
        b = isqrt(difference)
        if b * b == difference:
            smaller, larger = a - b, a + b
            if smaller > 1:
                return smaller, larger, iterations
        difference += 2 * a + 1
        a += 1

    return None, None, max_iterations


def _is_prime_u64(value: int) -> bool:
    """Deterministic Miller-Rabin primality check for unsigned 64-bit inputs."""
    if value < 2 or value >= _UINT64_LIMIT:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % prime == 0:
            return value == prime

    odd_part = value - 1
    twos = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        twos += 1

    for base in _MILLER_RABIN_BASES_64:
        base %= value
        if base == 0:
            continue
        witness = pow(base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _ in range(twos - 1):
            witness = pow(witness, 2, value)
            if witness == value - 1:
                break
        else:
            return False
    return True


def recover_rsa_private_key(
    modulus: int,
    public_exponent: int = 65537,
    max_iterations: int = 1_000_000,
) -> tuple[int, int, int]:
    """Recover a toy RSA key when bounded Fermat factoring finds prime factors.

    The factors must be distinct primes below 2**64 so their primality and
    Euler totient can be established exactly by this educational helper.
    """
    if not 1 < public_exponent < modulus:
        raise ValueError("public_exponent must be between 2 and modulus - 1")

    p, q, _ = fermat_factor(modulus, max_iterations)
    if p is None or q is None:
        raise ValueError("Fermat factorization did not find factors within the iteration limit")
    if p == q or not _is_prime_u64(p) or not _is_prime_u64(q):
        raise ValueError("Fermat factors must be distinct primes smaller than 2**64")

    totient = (p - 1) * (q - 1)
    try:
        private_exponent = mod_inverse_builtin(public_exponent, totient)
    except ValueError as exc:
        raise ValueError("public_exponent must be coprime to the RSA totient") from exc
    return p, q, private_exponent


def _convergents(numerator: int, denominator: int) -> Iterator[tuple[int, int]]:
    """Yield convergents of numerator/denominator as integer pairs."""
    previous_numerator, current_numerator = 0, 1
    previous_denominator, current_denominator = 1, 0
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        next_numerator = quotient * current_numerator + previous_numerator
        next_denominator = quotient * current_denominator + previous_denominator
        yield next_numerator, next_denominator
        previous_numerator, current_numerator = current_numerator, next_numerator
        previous_denominator, current_denominator = current_denominator, next_denominator
        numerator, denominator = denominator, remainder


def wiener_attack(modulus: int, public_exponent: int) -> WienerRecovery | None:
    """Recover RSA private data when a public key has a Wiener-vulnerable exponent.

    This educational check uses continued fractions and is not a general RSA
    factoring algorithm. It returns ``None`` when it finds no validated recovery.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    if not 1 < public_exponent < modulus:
        raise ValueError("public_exponent must be between 2 and modulus - 1")

    for multiplier, private_exponent in _convergents(public_exponent, modulus):
        if multiplier == 0:
            continue
        totient_candidate_numerator = public_exponent * private_exponent - 1
        if totient_candidate_numerator % multiplier:
            continue
        totient_candidate = totient_candidate_numerator // multiplier
        prime_sum = modulus - totient_candidate + 1
        discriminant = prime_sum * prime_sum - 4 * modulus
        if discriminant < 0:
            continue
        root = isqrt(discriminant)
        if root * root != discriminant or (prime_sum + root) % 2:
            continue
        p = (prime_sum + root) // 2
        q = (prime_sum - root) // 2
        if p > 1 and q > 1 and p * q == modulus:
            p, q = sorted((p, q))
            return WienerRecovery(private_exponent, p, q)
    return None


__all__ = [
    "PollardRhoResult",
    "RSAExponentiationResult",
    "SharedFactorFinding",
    "WienerRecovery",
    "batch_gcd",
    "fermat_factor",
    "hastad_broadcast",
    "pollard_rho_factor",
    "recover_rsa_private_key",
    "rsa_exponentiation_roundtrip",
    "wiener_attack",
]
