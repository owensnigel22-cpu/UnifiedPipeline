"""Mod-9 propagation layer over a CNF, run on top of an existing SAT solver.

**Honest positioning.** This is a *propagation heuristic*, not a SAT engine and
not a preimage attack. It performs Boolean constraint propagation (unit
propagation to a fixpoint, detecting forced literals and conflicts) and an
optional *casting-out-nines* feasibility check over declared integer bit-groups:
if the residue modulo 9 that a group must take is unreachable given the bits
already fixed, the partial assignment is a conflict and can be pruned before a
full solver explores it.

The "3.2x speedup on SHA-256 preimage instances" reported for the Shelbydon
SAT-solver write-up (see ``docs/references.md``) is **that project's claim**.
KeyLab measures its own pruning effect and claims no speedup here; the value of
this module is an auditable, pure-Python pruning check, not a performance record.

The mod-9 check is sound (it never prunes a satisfiable assignment) because an
integer's value modulo 9 equals the sum of its bit weights ``2**i mod 9`` over
the set bits, and the reachable residues from the still-free bits are exactly
the subset sums of their weights modulo 9. Only truncated / reduced-round /
constrained instances are intended; nothing here addresses full 64-round SHA-256.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

Clause = tuple[int, ...]


@dataclass(frozen=True)
class Mod9Group:
    """A bit-group whose integer value must be ``residue`` modulo 9.

    ``bits`` are positive DIMACS variables, least-significant bit first; bit
    ``i`` carries weight ``2**i``. ``residue`` is the required value mod 9.
    """

    bits: tuple[int, ...]
    residue: int

    def __post_init__(self) -> None:
        if any(type(bit) is not int or bit <= 0 for bit in self.bits):
            raise ValueError("Mod9Group bits must be positive DIMACS variables")
        if len(set(self.bits)) != len(self.bits):
            raise ValueError("Mod9Group bits must be unique")
        if type(self.residue) is not int or not 0 <= self.residue < 9:
            raise ValueError("Mod9Group residue must be in [0, 9)")


@dataclass(frozen=True)
class PropagationResult:
    """Outcome of one propagation pass."""

    implied: dict[int, bool]
    conflict: bool
    reason: str = ""
    passes: int = 0

    @property
    def ok(self) -> bool:
        """True when no conflict was detected."""
        return not self.conflict


def _literal_satisfied(literal: int, assignment: Mapping[int, bool]) -> bool | None:
    """Return the truth of ``literal`` under ``assignment``, or None if unassigned."""
    value = assignment.get(abs(literal))
    if value is None:
        return None
    return value if literal > 0 else not value


def _reachable_residues(weights: Sequence[int]) -> frozenset[int]:
    """Subset sums modulo 9 of the given bit weights (``0`` is always reachable)."""
    reachable = {0}
    for weight in weights:
        reachable |= {(existing + weight) % 9 for existing in reachable}
        if len(reachable) == 9:
            break
    return frozenset(reachable)


class Mod9Propagator:
    """Unit propagation plus a casting-out-nines conflict check over a CNF.

    Construct once from a formula's clauses (and any integer bit-groups), then
    call :meth:`propagate` with a partial assignment. The propagator deduces
    forced literals, reports conflicts, and never assigns a variable to two
    values. It decides nothing on its own: unresolved variables are left for the
    downstream solver.
    """

    def __init__(
        self,
        clauses: Sequence[Clause] | Sequence[Sequence[int]],
        *,
        groups: Sequence[Mod9Group] = (),
        max_variable: int | None = None,
    ) -> None:
        normalized: list[Clause] = []
        highest = 0
        for clause in clauses:
            row = tuple(clause)
            if any(type(literal) is not int or literal == 0 for literal in row):
                raise ValueError("clauses must contain nonzero integer literals")
            highest = max(highest, *(abs(literal) for literal in row)) if row else highest
            normalized.append(row)
        self._clauses: tuple[Clause, ...] = tuple(normalized)
        self._groups: tuple[Mod9Group, ...] = tuple(groups)
        if max_variable is not None:
            if type(max_variable) is not int or max_variable < highest:
                raise ValueError("max_variable must be an int >= the largest clause variable")
            highest = max_variable
        self.variable_count = highest

    @property
    def clauses(self) -> tuple[Clause, ...]:
        """The normalized clause database."""
        return self._clauses

    @property
    def groups(self) -> tuple[Mod9Group, ...]:
        """The declared mod-9 integer bit-groups."""
        return self._groups

    def _unit_propagate(self, assignment: dict[int, bool]) -> tuple[bool, str]:
        """Propagate units to a fixpoint, mutating ``assignment`` in place."""
        changed = True
        while changed:
            changed = False
            for clause in self._clauses:
                unassigned: list[int] = []
                satisfied = False
                for literal in clause:
                    truth = _literal_satisfied(literal, assignment)
                    if truth is True:
                        satisfied = True
                        break
                    if truth is None:
                        unassigned.append(literal)
                if satisfied:
                    continue
                if not unassigned:
                    return False, "unit propagation reached an all-false clause"
                if len(unassigned) == 1:
                    forced = unassigned[0]
                    assignment[abs(forced)] = forced > 0
                    changed = True
        return True, ""

    def _mod9_consistent(self, assignment: Mapping[int, bool]) -> tuple[bool, str]:
        """Check every group's residue is still reachable under ``assignment``."""
        for index, group in enumerate(self._groups):
            fixed = 0
            free_weights: list[int] = []
            for position, bit in enumerate(group.bits):
                weight = pow(2, position, 9)
                value = assignment.get(bit)
                if value is None:
                    free_weights.append(weight)
                elif value:
                    fixed = (fixed + weight) % 9
            reachable = {(fixed + delta) % 9 for delta in _reachable_residues(free_weights)}
            if group.residue not in reachable:
                return False, f"mod-9 residue {group.residue} unreachable for group {index}"
        return True, ""

    def propagate(self, assignment: Mapping[int, bool] | None = None) -> PropagationResult:
        """Propagate from ``assignment`` and return the deduced literals/conflict.

        The input mapping is never mutated. ``implied`` contains only variables
        newly fixed by propagation (the inputs are excluded). A conflict sets
        ``conflict=True`` with a human-readable ``reason``.
        """
        working: dict[int, bool] = {}
        if assignment is not None:
            for variable, value in assignment.items():
                if type(variable) is not int or variable <= 0:
                    raise ValueError("assignment keys must be positive DIMACS variables")
                if type(value) is not bool:
                    raise TypeError("assignment values must be bool")
                working[variable] = value
        given = dict(working)

        passes = 0
        while True:
            passes += 1
            ok, reason = self._unit_propagate(working)
            if not ok:
                return self._result(given, working, conflict=True, reason=reason, passes=passes)
            consistent, mod_reason = self._mod9_consistent(working)
            if not consistent:
                return self._result(given, working, conflict=True, reason=mod_reason, passes=passes)
            # The mod-9 layer only prunes; it forces no new literal, so one more
            # unit-propagation pass cannot change anything and we have a fixpoint.
            return self._result(given, working, conflict=False, reason="", passes=passes)

    @staticmethod
    def _result(
        given: Mapping[int, bool],
        working: Mapping[int, bool],
        *,
        conflict: bool,
        reason: str,
        passes: int,
    ) -> PropagationResult:
        implied = {var: val for var, val in working.items() if var not in given}
        return PropagationResult(implied=implied, conflict=conflict, reason=reason, passes=passes)


__all__ = ["Mod9Group", "Mod9Propagator", "PropagationResult"]
