"""Tests for validated, optional LLM cube planning."""

import json
from types import SimpleNamespace

from keylab import cli
from keylab.hashes.llm_agents import AgentCubePlan, plan_sha256_cube_bits
from keylab.hashes.reduced import sha256_reduced
from keylab.hashes.sha256_cnf import sha256_hash_preimage_cnf
from keylab.sat.parallel import ParallelCubeResult


class _FakeResponses:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return SimpleNamespace(output_text=self.handler(kwargs))


class _FakeClient:
    def __init__(self, handler):
        self.responses = _FakeResponses(handler)


def test_two_agent_cube_plan_is_validated_merged_and_hash_is_not_disclosed() -> None:
    def reply(request):
        bits = [2, 4] if "message-schedule analyst" in request["instructions"] else [3, 5]
        return json.dumps({"bit_indices": bits})

    client = _FakeClient(reply)
    plan = plan_sha256_cube_bits(
        rounds=12,
        message_length=1,
        input_bit_count=8,
        clause_count=400,
        variable_count=100,
        depth=2,
        fixed_bit_indices={0},
        client=client,
    )

    assert plan.bit_indices == (2, 3)
    assert plan.agent_suggestions == {"schedule_analyst": (2, 4), "sat_planner": (3, 5)}
    assert all("target" not in request["input"].lower() for request in client.responses.requests)
    assert all("digest" not in request["input"].lower() for request in client.responses.requests)
    assert all("candidate" not in request["input"].lower() for request in client.responses.requests)


def test_bad_agent_suggestions_fall_back_to_available_input_bits() -> None:
    client = _FakeClient(lambda _request: '{"bit_indices": [0, 99]}')
    plan = plan_sha256_cube_bits(
        rounds=8,
        message_length=1,
        input_bit_count=8,
        clause_count=20,
        variable_count=10,
        depth=2,
        fixed_bit_indices={0},
        client=client,
    )
    assert plan.bit_indices == (1, 2)
    assert len(plan.warnings) == 3
    assert all("rejected" in warning for warning in plan.warnings[:2])


def test_agent_request_failures_keep_complete_deterministic_plan() -> None:
    def fail(_request):
        raise ConnectionError("network unavailable")

    client = _FakeClient(fail)
    plan = plan_sha256_cube_bits(
        rounds=8,
        message_length=1,
        input_bit_count=8,
        clause_count=20,
        variable_count=10,
        depth=2,
        client=client,
    )
    assert plan.bit_indices == (0, 1)
    assert len(plan.warnings) == 3
    assert "network unavailable" not in " ".join(plan.warnings)


def test_agent_solve_cli_verifies_sat_candidate_locally(monkeypatch, capsys) -> None:
    candidate = b"x"
    target = sha256_reduced(candidate, rounds=1)
    model = sha256_hash_preimage_cnf(target, message_length=1, rounds=1)
    input_values = {
        variable: bool((candidate[0] >> (7 - index)) & 1)
        for index, variable in enumerate(model.input_bits)
    }
    monkeypatch.setattr(
        cli,
        "plan_sha256_cube_bits",
        lambda **_kwargs: AgentCubePlan((0,), {"test": (0,)}, ()),
    )
    monkeypatch.setattr(
        cli,
        "solve_parallel_cubes",
        lambda *_args, **_kwargs: ParallelCubeResult(
            "SATISFIABLE", 2, 1, 1, input_values, (model.input_bits[0],)
        ),
    )

    status = cli.main(
        [
            "sha256-agent-solve",
            "--target",
            target.hex(),
            "--message-length",
            "1",
            "--rounds",
            "1",
            "--solver",
            "mock-solver",
            "--cube-depth",
            "1",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["verified"] is True
    assert output["candidate_hex"] == candidate.hex()
