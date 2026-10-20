"""Concrete-folding and symbolic 32-bit words over Keylab's CNF gates."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from keylab.sat.cnf import CNF

_WIDTH = 32
_MASK = (1 << _WIDTH) - 1


@dataclass(frozen=True)
class BitVec32:
    """A 32-bit word that stays concrete until a symbolic operation is needed.

    Symbolic bits are signed DIMACS literals in least-significant-bit-first
    order. ``add`` is unsigned ADD32 modulo 2**32; its carry-out is discarded,
    as required by SHA-256 word arithmetic. This is not a wide integer type.
    """

    cnf: CNF
    _concrete: int | None = None
    _bits: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        if (self._concrete is None) == (self._bits is None):
            raise ValueError("exactly one of _concrete or _bits must be provided")
        if self._concrete is not None:
            if type(self._concrete) is not int or not 0 <= self._concrete <= _MASK:
                raise ValueError("concrete value must be an unsigned 32-bit integer")
        else:
            assert self._bits is not None
            if len(self._bits) != _WIDTH:
                raise ValueError("symbolic words must contain exactly 32 literals")
            if any(type(literal) is not int or literal == 0 or abs(literal) > self.cnf.variable_count for literal in self._bits):
                raise ValueError("symbolic word contains an invalid or unallocated literal")

    @classmethod
    def from_int(cls, cnf: CNF, value: int) -> BitVec32:
        """Create a concrete word without allocating variables or clauses."""
        if type(value) is not int:
            raise TypeError("value must be an integer")
        return cls(cnf=cnf, _concrete=value & _MASK)

    @classmethod
    def symbolic(cls, cnf: CNF, label: str = "word") -> BitVec32:
        """Allocate 32 independent symbolic input bits."""
        return cls(cnf=cnf, _bits=tuple(cnf.input_var(f"{label}[{index}]") for index in range(_WIDTH)))

    @property
    def is_concrete(self) -> bool:
        return self._concrete is not None

    def _same_cnf(self, other: BitVec32) -> None:
        if not isinstance(other, BitVec32) or other.cnf is not self.cnf:
            raise ValueError("bit-vector operands must use the same CNF instance")

    def _as_bits(self) -> tuple[int, ...]:
        if self._bits is not None:
            return self._bits
        assert self._concrete is not None
        zero = self.cnf.constant(False)
        one = self.cnf.constant(True)
        return tuple(one if (self._concrete >> index) & 1 else zero for index in range(_WIDTH))

    def to_literals(self) -> tuple[int, ...]:
        """Materialize a concrete word as CNF constants or return symbolic bits."""
        return self._as_bits()

    def rotr(self, amount: int) -> BitVec32:
        """Rotate right, folding concrete inputs without touching the CNF."""
        if type(amount) is not int:
            raise TypeError("rotation amount must be an integer")
        amount %= _WIDTH
        if self._concrete is not None:
            if amount == 0:
                return self
            value = ((self._concrete >> amount) | (self._concrete << (_WIDTH - amount))) & _MASK
            return BitVec32.from_int(self.cnf, value)
        assert self._bits is not None
        return BitVec32(cnf=self.cnf, _bits=tuple(self._bits[(index + amount) % _WIDTH] for index in range(_WIDTH)))

    def xor(self, other: BitVec32) -> BitVec32:
        """Bitwise XOR with concrete folding and literal-level simplification."""
        self._same_cnf(other)
        if self._concrete is not None and other._concrete is not None:
            return BitVec32.from_int(self.cnf, self._concrete ^ other._concrete)
        if self._concrete is not None and other._bits is not None:
            bits = tuple(-bit if (self._concrete >> index) & 1 else bit for index, bit in enumerate(other._bits))
            return BitVec32(cnf=self.cnf, _bits=bits)
        if other._concrete is not None and self._bits is not None:
            bits = tuple(-bit if (other._concrete >> index) & 1 else bit for index, bit in enumerate(self._bits))
            return BitVec32(cnf=self.cnf, _bits=bits)
        left, right = self._as_bits(), other._as_bits()
        return BitVec32(cnf=self.cnf, _bits=tuple(self.cnf.xor(a, b) for a, b in zip(left, right, strict=True)))

    def and_(self, other: BitVec32) -> BitVec32:
        """Bitwise AND, folding fully concrete words."""
        self._same_cnf(other)
        if self._concrete is not None and other._concrete is not None:
            return BitVec32.from_int(self.cnf, self._concrete & other._concrete)
        left, right = self._as_bits(), other._as_bits()
        return BitVec32(cnf=self.cnf, _bits=tuple(self.cnf.and_gate(a, b) for a, b in zip(left, right, strict=True)))

    def or_(self, other: BitVec32) -> BitVec32:
        """Bitwise OR, folding fully concrete words."""
        self._same_cnf(other)
        if self._concrete is not None and other._concrete is not None:
            return BitVec32.from_int(self.cnf, self._concrete | other._concrete)
        left, right = self._as_bits(), other._as_bits()
        return BitVec32(cnf=self.cnf, _bits=tuple(self.cnf.or_gate(a, b) for a, b in zip(left, right, strict=True)))

    def add(self, other: BitVec32) -> BitVec32:
        """Return ADD32 modulo 2**32; no carry-out bit is retained."""
        self._same_cnf(other)
        if self._concrete is not None and other._concrete is not None:
            return BitVec32.from_int(self.cnf, self._concrete + other._concrete)
        left, right = self._as_bits(), other._as_bits()
        carry = self.cnf.constant(False)
        result: list[int] = []
        for index, (left_bit, right_bit) in enumerate(zip(left, right, strict=True)):
            if index == _WIDTH - 1:
                result.append(self.cnf.xor(self.cnf.xor(left_bit, right_bit), carry))
            else:
                sum_bit, carry = self.cnf.full_adder(left_bit, right_bit, carry)
                result.append(sum_bit)
        return BitVec32(cnf=self.cnf, _bits=tuple(result))

    def sigma0(self) -> BitVec32:
        """SHA-256 small sigma0: ROTR7(x) XOR ROTR18(x) XOR SHR3(x)."""
        if self._concrete is not None:
            value = self._concrete
            result = ((value >> 7) | (value << 25)) ^ ((value >> 18) | (value << 14)) ^ (value >> 3)
            return BitVec32.from_int(self.cnf, result)
        shifted = tuple(self._bits[index + 3] if index + 3 < _WIDTH else self.cnf.constant(False) for index in range(_WIDTH))
        return self.rotr(7).xor(self.rotr(18)).xor(BitVec32(cnf=self.cnf, _bits=shifted))

    def extract_word(self, model: Mapping[int, bool] | Sequence[bool] | None = None) -> int:
        """Evaluate a symbolic word from a DIMACS model; return concrete values directly."""
        if self._concrete is not None:
            return self._concrete
        if model is None:
            raise ValueError("a model is required to extract a symbolic word")
        assert self._bits is not None
        value = 0
        for index, literal in enumerate(self._bits):
            variable = abs(literal)
            try:
                raw = model[variable]
            except (KeyError, IndexError) as exc:
                raise ValueError(f"model does not assign variable {variable}") from exc
            bit = bool(raw) if literal > 0 else not bool(raw)
            if bit:
                value |= 1 << index
        return value


__all__ = ["BitVec32"]
