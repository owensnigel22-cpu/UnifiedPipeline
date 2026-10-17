"""Optional LLM heuristics for planning bounded SHA-256 SAT cube partitions.

LLM suggestions only affect which input bits define a complete SAT partition.
They never decide satisfiability or verify a recovered message. The digest and
candidate input are deliberately excluded from requests sent to the provider.
"""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentCubePlan:
    """Validated bit-index ordering proposed by independent planning roles."""

    bit_indices: tuple[int, ...]
    agent_suggestions: dict[str, tuple[int, ...]]
    warnings: tuple[str, ...]


_ROLES = {
    "schedule_analyst": (
        "You are a SHA-256 message-schedule analyst. Select input-bit indices for a SAT cube split. "
        "Choose exactly split_depth distinct integers in [0, input_bit_count). Prefer bits with "
        "early schedule influence and broad downstream coverage. Return only JSON with an "
        "integer array field named bit_indices. This is a heuristic; do not claim it improves speed."
    ),
    "sat_planner": (
        "You are a SAT cube-and-conquer planner. Independently select exactly split_depth distinct "
        "input-bit indices in [0, input_bit_count) for a complete cube partition. Consider balanced "
        "branching and avoid simply copying a presumed answer. Return only JSON with an integer "
        "array field named bit_indices. Do not claim a performance gain without measurements."
    ),
}


def _parse_suggestion(text: str, *, bit_count: int, depth: int) -> tuple[int, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("agent response did not contain a JSON object")
        payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict) or not isinstance(payload.get("bit_indices"), list):
        raise TypeError("agent response must contain a bit_indices array")
    indices = payload["bit_indices"]
    if len(indices) != depth or any(type(index) is not int for index in indices):
        raise ValueError(f"agent must return exactly {depth} integer bit indices")
    if len(set(indices)) != len(indices) or any(not 0 <= index < bit_count for index in indices):
        raise ValueError("agent returned duplicate or out-of-range bit indices")
    return tuple(indices)


def plan_sha256_cube_bits(
    *,
    rounds: int,
    message_length: int,
    input_bit_count: int,
    clause_count: int,
    variable_count: int,
    depth: int,
    fixed_bit_indices: set[int] | frozenset[int] = frozenset(),
    model: str = "gpt-4.1-mini",
    client: Any | None = None,
) -> AgentCubePlan:
    """Ask two LLM roles for cube-bit order, then validate and merge locally.

    Requests contain model dimensions and fixed indices only. They do not
    contain the target digest, fixed-bit values, DIMACS formula, or candidate.
    Set OPENAI_API_KEY and install keylab[llm] to enable live requests.
    Pass a compatible client object for tests or an OpenAI-compatible endpoint.
    """
    if not 1 <= depth <= 16:
        raise ValueError("depth must be between 1 and 16")
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    if message_length < 0 or input_bit_count < 0:
        raise ValueError("message length and input bit count must be nonnegative")
    available = tuple(index for index in range(input_bit_count) if index not in fixed_bit_indices)
    if any(type(index) is not int or not 0 <= index < input_bit_count for index in fixed_bit_indices):
        raise ValueError("fixed input bit indices must refer to existing input bits")
    if len(available) < depth:
        raise ValueError("not enough unfixed input bits for the requested cube depth")

    if client is None:
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("set OPENAI_API_KEY and install keylab[llm] to use LLM agents")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("install the optional LLM dependency with pip install 'keylab[llm]'") from exc
        client = OpenAI()

    context = {
        "rounds": rounds,
        "message_length_bytes": message_length,
        "input_bit_count": input_bit_count,
        "free_input_bit_count": len(available),
        "fixed_input_bit_indices": sorted(fixed_bit_indices),
        "variable_count": variable_count,
        "clause_count": clause_count,
        "split_depth": depth,
        "input_bit_order": "byte order, most-significant bit first",
    }

    def ask(role: str, instructions: str) -> tuple[str, str | None]:
        try:
            response = client.responses.create(
                model=model,
                instructions=instructions,
                input=json.dumps(context, sort_keys=True),
                max_output_tokens=300,
            )
            output_text = response.output_text
            if not isinstance(output_text, str):
                raise TypeError("agent response had no text output")
            return role, output_text
        except Exception as exc:  # noqa: BLE001 - isolate optional provider failures per role
            return role, f"__ERROR__:{type(exc).__name__}"

    with ThreadPoolExecutor(max_workers=len(_ROLES)) as executor:
        responses = tuple(executor.map(lambda item: ask(*item), _ROLES.items()))

    suggestions: dict[str, tuple[int, ...]] = {}
    warnings: list[str] = []
    for role, text in responses:
        if text.startswith("__ERROR__:"):
            warnings.append(f"{role} request failed ({text.removeprefix('__ERROR__:')})")
            continue
        try:
            suggestion = _parse_suggestion(text, bit_count=input_bit_count, depth=depth)
            if any(index not in available for index in suggestion):
                raise ValueError("agent selected an input bit already fixed by the model")
            suggestions[role] = suggestion
        except (TypeError, ValueError) as exc:
            warnings.append(f"{role} suggestion rejected: {exc}")

    # Deterministic ordering and defaults preserve a complete partition.
    chosen: list[int] = []
    for suggestion_index in range(depth):
        for role in _ROLES:
            suggestion = suggestions.get(role, ())
            if suggestion_index < len(suggestion):
                index = suggestion[suggestion_index]
                if index not in chosen and len(chosen) < depth:
                    chosen.append(index)
    if len(chosen) < depth:
        warnings.append("using deterministic input-bit defaults to complete the split plan")
        chosen.extend(index for index in available if index not in chosen and len(chosen) < depth)
    return AgentCubePlan(tuple(chosen), suggestions, tuple(warnings))


__all__ = ["AgentCubePlan", "plan_sha256_cube_bits"]

