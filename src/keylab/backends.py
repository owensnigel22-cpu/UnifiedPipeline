"""Optional native acceleration backends with dependency-free fallbacks."""

from __future__ import annotations

from importlib.util import find_spec

_OPTIONAL_MODULES = {
    "cryptography": "cryptography",
    "pycryptodome": "Crypto",
    "coincurve": "coincurve",
    "fastecdsa": "fastecdsa",
    "gmpy2": "gmpy2",
    "python-sat": "pysat",
    "pycosat": "pycosat",
    "cdclkit": "cdclkit",
    "pycryptosat": "pycryptosat",
}


def backend_info() -> dict[str, bool]:
    """Report which optional Python backends can be imported in this environment."""
    return {name: find_spec(module) is not None for name, module in _OPTIONAL_MODULES.items()}


def modular_pow(base: int, exponent: int, modulus: int, *, secure: bool = False) -> int:
    """Compute modular exponentiation, using GMP for large inputs when available.

    Set ``secure=True`` only when the caller requires a side-channel-resistant
    exponentiation. This requires gmpy2 and an odd modulus; it deliberately does
    not fall back to Python's variable-time ``pow`` in that mode.
    """
    if type(base) is not int or type(exponent) is not int or type(modulus) is not int:
        raise TypeError("base, exponent, and modulus must be integers")
    if exponent < 0 or modulus <= 1:
        raise ValueError("exponent must be nonnegative and modulus must exceed one")
    if secure:
        if exponent == 0 or modulus % 2 == 0:
            raise ValueError("secure modular exponentiation requires a positive exponent and odd modulus")
        try:
            import gmpy2
        except ImportError as exc:
            raise RuntimeError("secure modular exponentiation requires gmpy2") from exc
        return int(gmpy2.powmod_sec(base, exponent, modulus))

    if max(abs(base).bit_length(), exponent.bit_length(), modulus.bit_length()) >= 512:
        try:
            import gmpy2
        except ImportError:
            pass
        else:
            return int(gmpy2.powmod(base, exponent, modulus))
    return pow(base, exponent, modulus)


def integer_nth_root(value: int, exponent: int) -> tuple[int, bool]:
    """Return the floor nth root and whether it is exact, using GMP when installed."""
    if type(value) is not int or type(exponent) is not int:
        raise TypeError("value and exponent must be integers")
    if value < 0 or exponent < 1:
        raise ValueError("value must be nonnegative and exponent must be positive")
    try:
        import gmpy2
    except ImportError:
        low, high = 0, 1 << ((value.bit_length() + exponent - 1) // exponent)
        while low <= high:
            middle = (low + high) // 2
            candidate = middle**exponent
            if candidate == value:
                return middle, True
            if candidate < value:
                low = middle + 1
            else:
                high = middle - 1
        return high, False
    root, exact = gmpy2.iroot(value, exponent)
    return int(root), bool(exact)


__all__ = ["backend_info", "integer_nth_root", "modular_pow"]
