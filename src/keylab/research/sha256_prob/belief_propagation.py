"""Loopy sum-product belief propagation over binary factor graphs.

The engine (:class:`FactorGraph`, :func:`run_bp`) is a standard normalized
sum-product message-passing solver. On a tree it is **exact** — the returned
marginals equal the true marginals (pinned in the tests against brute force). On a
loopy graph, such as a hash circuit, it has **no** convergence guarantee.

:func:`solve_truncated` applies it to a reduced-round, *truncated* SHA-256 preimage:
it conditions the low ``target_bits`` output bits of the ``rounds``-round
compression (built by :mod:`keylab.research.sha256_prob._circuit`) on a target for
which a preimage is known to exist, runs BP over the bit factor-graph, decodes the
free message bits from their marginals, and **forward-verifies** the decode. The
result reports ``converged`` and ``verified`` honestly: a non-converging or wrong
decode is returned as such, never dressed up as a success.

**Measured behaviour (honest note).** Loopy BP does *not* converge on the SHA-256
circuit (the adds/Maj/Ch make it strongly loopy), but with many free bits the
marginal-rounded decode still lands in the large truncated-preimage solution set for
*easy* instances. Measured over 5 seeds at ``n_bits=64``, ``max_iters=60``:
one round verifies 5/5 at ``target_bits=8``, 2/5 at 16, 1/5 at 24; two rounds
verifies 0/5. So BP is a genuine (if weak) solver for small one-round truncations and
degrades quickly — it is **not** a SHA-256 inverter, and no full 64-round preimage is
attempted. ``converged`` is almost always ``False`` here; ``verified`` is the
decode's forward-verified truth.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.research.sha256_prob._circuit import build_compression_circuit

_EPS = 1e-300


@dataclass(frozen=True)
class Factor:
    """A factor over binary variables: ``table[j]`` is the potential of the joint
    assignment whose bit ``k`` (value ``1 << k``) is the value of ``variables[k]``.
    """

    variables: tuple[int, ...]
    table: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.table) != (1 << len(self.variables)):
            raise ValueError("table length must be 2**len(variables)")


@dataclass
class FactorGraph:
    """A factor graph over ``num_vars`` binary variables and a list of factors."""

    num_vars: int
    factors: list[Factor]

    def incidence(self) -> list[list[int]]:
        """Return, for each variable, the indices of the factors that touch it."""
        incident: list[list[int]] = [[] for _ in range(self.num_vars)]
        for f_index, factor in enumerate(self.factors):
            for var in factor.variables:
                incident[var].append(f_index)
        return incident


@dataclass(frozen=True)
class BPResult:
    """Outcome of :func:`solve_truncated`."""

    converged: bool
    verified: bool
    iterations: int
    rounds: int
    target_bits: int
    n_free_bits: int
    marginals: dict[tuple[int, int], float]  # (word, bit) -> P(bit == 1)
    candidate: bytes | None                   # the decoded 64-byte block, if any


def _normalize(pair: list[float]) -> list[float]:
    total = pair[0] + pair[1]
    if total <= _EPS:
        return [0.5, 0.5]
    return [pair[0] / total, pair[1] / total]


def _hard_pins(graph: FactorGraph) -> list[int | None]:
    """Return per-variable hard pin (0/1) from unary factors with a zeroed value.

    A unary factor ``(1, 0)``/``(0, 1)`` forces its variable, so every useful
    message out of that variable is constant. Treating such variables as pinned
    removes the heavy message updates on fan-out wires like the shared const-zero.
    """
    pins: list[int | None] = [None] * graph.num_vars
    for factor in graph.factors:
        if len(factor.variables) == 1:
            if factor.table == (1.0, 0.0):
                pins[factor.variables[0]] = 0
            elif factor.table == (0.0, 1.0):
                pins[factor.variables[0]] = 1
    return pins


def run_bp(
    graph: FactorGraph,
    *,
    max_iters: int = 200,
    damping: float = 0.5,
    tol: float = 1e-6,
) -> tuple[list[list[float]], bool, int]:
    """Run normalized sum-product BP; return (beliefs, converged, iterations).

    ``beliefs[v]`` is ``[P(v == 0), P(v == 1)]``. ``converged`` is True when the
    largest belief change between sweeps fell below ``tol`` before ``max_iters``.
    Variables pinned by a hard unary factor are held fixed for speed.
    """
    if not 0.0 <= damping < 1.0:
        raise ValueError("damping must be in [0, 1)")
    pins = _hard_pins(graph)
    # Messages indexed by factor then position within that factor.
    m_fv: list[list[list[float]]] = []
    m_vf: list[list[list[float]]] = []
    for factor in graph.factors:
        m_fv.append([[0.5, 0.5] for _ in factor.variables])
        m_vf.append([[0.5, 0.5] for _ in factor.variables])
    # For each variable, the (factor_index, position) slots that reference it.
    slots: list[list[tuple[int, int]]] = [[] for _ in range(graph.num_vars)]
    for f_index, factor in enumerate(graph.factors):
        for position, var in enumerate(factor.variables):
            slots[var].append((f_index, position))
    # Pre-pin constant variable->factor messages once.
    for var, pin in enumerate(pins):
        if pin is not None:
            fixed = [1.0, 0.0] if pin == 0 else [0.0, 1.0]
            for f_index, position in slots[var]:
                m_vf[f_index][position] = fixed

    def beliefs() -> list[list[float]]:
        out: list[list[float]] = []
        for var in range(graph.num_vars):
            if pins[var] is not None:
                out.append([1.0, 0.0] if pins[var] == 0 else [0.0, 1.0])
                continue
            prod = [1.0, 1.0]
            for f_index, position in slots[var]:
                msg = m_fv[f_index][position]
                prod[0] *= msg[0]
                prod[1] *= msg[1]
            out.append(_normalize(prod))
        return out

    prev = beliefs()
    converged = False
    iterations = 0
    for iterations in range(1, max_iters + 1):
        # Variable -> factor (skip pinned variables: their messages are constant).
        for var in range(graph.num_vars):
            if pins[var] is not None:
                continue
            var_slots = slots[var]
            for f_index, position in var_slots:
                prod = [1.0, 1.0]
                for other_f, other_pos in var_slots:
                    if other_f == f_index and other_pos == position:
                        continue
                    msg = m_fv[other_f][other_pos]
                    prod[0] *= msg[0]
                    prod[1] *= msg[1]
                m_vf[f_index][position] = _normalize(prod)
        # Factor -> variable.
        for f_index, factor in enumerate(graph.factors):
            variables = factor.variables
            n = len(variables)
            incoming = m_vf[f_index]
            for position, var in enumerate(variables):
                if pins[var] is not None:
                    continue  # the belief at a pinned var is fixed; no need to update
                out = [0.0, 0.0]
                for assignment in range(1 << n):
                    weight = factor.table[assignment]
                    if weight == 0.0:
                        continue
                    for other_pos in range(n):
                        if other_pos == position:
                            continue
                        weight *= incoming[other_pos][(assignment >> other_pos) & 1]
                    out[(assignment >> position) & 1] += weight
                new = _normalize(out)
                old = m_fv[f_index][position]
                m_fv[f_index][position] = _normalize([
                    damping * old[0] + (1.0 - damping) * new[0],
                    damping * old[1] + (1.0 - damping) * new[1],
                ])
        current = beliefs()
        delta = max(
            (abs(current[v][1] - prev[v][1]) for v in range(graph.num_vars)),
            default=0.0,
        )
        prev = current
        if delta < tol:
            converged = True
            break
    return prev, converged, iterations


def _circuit_factor_graph(circuit, conditioned: dict[int, int]) -> FactorGraph:
    """Translate a compression circuit into a factor graph, pinning ``conditioned``.

    ``conditioned`` maps output (or const) var ids to a forced 0/1 value.
    """
    factors: list[Factor] = []
    for kind, out, data in circuit.gates:
        if kind == "const":
            factors.append(_pin(out, data[0]))
        elif kind == "input":
            continue  # free variable, uniform prior
        elif kind == "xor":
            variables = (out, *data)
            table = tuple(
                1.0 if (assignment.bit_count() & 1) == 0 else 0.0
                for assignment in range(1 << len(variables))
            )
            factors.append(Factor(variables, table))
        elif kind == "maj":
            factors.append(_gate_factor(out, data, _maj_bit))
        elif kind == "ch":
            factors.append(_gate_factor(out, data, _ch_bit))
    for var, value in conditioned.items():
        factors.append(_pin(var, value))
    return FactorGraph(circuit.num_vars, factors)


def _pin(var: int, value: int) -> Factor:
    return Factor((var,), (1.0, 0.0) if value == 0 else (0.0, 1.0))


def _maj_bit(a: int, b: int, c: int) -> int:
    return 1 if (a + b + c) >= 2 else 0


def _ch_bit(e: int, f: int, g: int) -> int:
    return f if e else g


def _gate_factor(out: int, inputs: tuple[int, ...], op) -> Factor:
    variables = (out, *inputs)
    n = len(variables)
    table = []
    for assignment in range(1 << n):
        bits = [(assignment >> k) & 1 for k in range(n)]
        table.append(1.0 if bits[0] == op(*bits[1:]) else 0.0)
    return Factor(variables, tuple(table))


def solve_truncated(
    target_bits: int,
    n_bits: int,
    *,
    rounds: int = 2,
    target: bytes | None = None,
    max_iters: int = 200,
    damping: float = 0.6,
    seed: int = 0,
) -> BPResult:
    """Attempt a truncated, reduced-round preimage with loopy belief propagation.

    ``n_bits`` free message bits feed the ``rounds``-round compression; the low
    ``target_bits`` output bits are conditioned. When ``target`` is ``None`` a
    random free assignment (from ``seed``) generates a target digest, so a preimage
    is *guaranteed to exist* and any failure is BP's, reported honestly. BP decodes
    the free bits from their marginals and the decode is forward-verified by
    re-evaluating the circuit; ``verified`` is the truth of that check.
    """
    if type(target_bits) is not int or not 1 <= target_bits <= 256:
        raise ValueError("target_bits must be between 1 and 256")
    if type(n_bits) is not int or not 1 <= n_bits <= 512:
        raise ValueError("n_bits must be between 1 and 512")

    circuit = build_compression_circuit(rounds, free_input_bits=n_bits)
    output_order = [var for word in circuit.output_words for var in word]  # LSB-first per word
    conditioned_vars = output_order[:target_bits]

    rng = _Lcg(seed)
    free_vars = [var for var, _word, _bit in circuit.input_bits]
    planted = {var: rng.bit() for var in free_vars}
    produced = circuit.evaluate(planted)
    if target is None:
        target_values = {
            conditioned_vars[i]: _output_bit(produced, output_order, conditioned_vars[i])
            for i in range(target_bits)
        }
    else:
        if len(target) != 32:
            raise ValueError("target must be exactly 32 bytes when provided")
        target_words = [int.from_bytes(target[i : i + 4], "big") for i in range(0, 32, 4)]
        target_values = {}
        for i in range(target_bits):
            var = conditioned_vars[i]
            word_index, bit_index = divmod(i, 32)
            target_values[var] = (target_words[word_index] >> bit_index) & 1

    graph = _circuit_factor_graph(circuit, target_values)
    beliefs, converged, iterations = run_bp(
        graph, max_iters=max_iters, damping=damping,
    )

    decode = {var: (1 if beliefs[var][1] >= 0.5 else 0) for var in free_vars}
    produced_decode = circuit.evaluate(decode)
    verified = all(
        _output_bit(produced_decode, output_order, var) == value
        for var, value in target_values.items()
    )
    candidate = _block_from_decode(circuit, decode) if verified else None
    marginals = {
        (word, bit): beliefs[var][1] for var, word, bit in circuit.input_bits
    }
    return BPResult(
        converged=converged,
        verified=verified,
        iterations=iterations,
        rounds=rounds,
        target_bits=target_bits,
        n_free_bits=n_bits,
        marginals=marginals,
        candidate=candidate,
    )


def _output_bit(words: list[int], output_order: list[int], var: int) -> int:
    index = output_order.index(var)
    word_index, bit_index = divmod(index, 32)
    return (words[word_index] >> bit_index) & 1


def _block_from_decode(circuit, decode: dict[int, int]) -> bytes:
    words = [0] * 16
    for var, word, bit in circuit.input_bits:
        if decode.get(var, 0):
            words[word] |= 1 << bit
    return b"".join(w.to_bytes(4, "big") for w in words)


class _Lcg:
    """A tiny deterministic bit source (SplitMix-style) for reproducible planting."""

    def __init__(self, seed: int) -> None:
        self._state = (seed * 0x2545F4914F6CDD1D + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF

    def bit(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return (z >> 31) & 1


__all__ = [
    "BPResult",
    "Factor",
    "FactorGraph",
    "run_bp",
    "solve_truncated",
]
