import hashlib
import json
from io import BytesIO

import pytest

from keylab.cli import main
from keylab.hashes.reduced import (
    _sha_compress,
    invert_choice_words,
    invert_majority_word,
    sha256_backward_trace,
    sha256_forward_feed,
    sha256_reduced,
    sha256_reduced_stream,
    sha256_reverse_compress,
    sha256_schedule_dependencies,
    sha256_schedule_words,
)


@pytest.mark.parametrize("rounds", [1, 8, 64])
def test_sha256_known_block_reverse_trace_recovers_each_boundary(rounds: int) -> None:
    block = bytes(range(64))
    output = _sha_compress(block, (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19), rounds)
    trace = sha256_reverse_compress(output, block, rounds=rounds)
    assert trace.rounds == rounds
    assert len(trace.working_states) == rounds + 1
    assert trace.working_states[0] == trace.initial_state
    assert tuple((value - initial) & 0xFFFFFFFF for value, initial in zip(output, trace.initial_state)) == (
        trace.working_states[-1]
    )


def test_sha256_known_block_reverse_trace_rejects_wrong_block_or_output() -> None:
    block = bytes(range(64))
    output = _sha_compress(block, (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19), 8)
    with pytest.raises(ValueError, match="do not compress"):
        sha256_reverse_compress(output, bytes(reversed(block)), rounds=8)
    with pytest.raises(ValueError, match="do not compress"):
        sha256_reverse_compress((*output[:-1], output[-1] ^ 1), block, rounds=8)


def test_sha256_reverse_compress_cli_emits_verified_state_trace(capsys) -> None:
    block = bytes(range(64))
    initial = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
    output = _sha_compress(block, initial, rounds=8)
    initial_hex = b"".join(word.to_bytes(4, "big") for word in initial).hex()
    output_hex = b"".join(word.to_bytes(4, "big") for word in output).hex()
    assert main(
        [
            "sha256-reverse-compress",
            "--output-state",
            output_hex,
            "--block",
            block.hex(),
            "--rounds",
            "8",
            "--initial-state",
            initial_hex,
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["initial_state_verified"] is True
    assert len(result["working_states"]) == 9
    assert result["working_states"][0] == [f"{word:08x}" for word in initial]


@pytest.mark.parametrize("suffix", [b"", b"short suffix", bytes(range(100))])
def test_sha256_forward_feed_prepends_one_512_bit_block(suffix: bytes) -> None:
    prefix_block = bytes(range(64))
    trace = sha256_forward_feed(prefix_block, suffix)
    assert trace.verified_against_hashlib is True
    assert trace.digest == hashlib.sha256(prefix_block + suffix).digest()
    assert all(len(block) == 64 for block in trace.padded_suffix_blocks)


def test_sha256_forward_feed_cli_checks_expected_digest(capsys) -> None:
    prefix_block = bytes(range(64))
    suffix = b"appended bytes"
    expected = hashlib.sha256(prefix_block + suffix).hexdigest()
    assert main(
        [
            "sha256-forward-feed",
            "--prefix-block",
            prefix_block.hex(),
            "--suffix",
            suffix.hex(),
            "--target",
            expected,
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["prefix_block_bits"] == 512
    assert result["forward_feed_verified_against_hashlib"] is True
    assert result["target_matches"] is True


def test_sha256_backward_ledger_can_reverse_known_block_to_round_32(capsys) -> None:
    message = b"abc"
    block = message + b"\x80" + b"\0" * (56 - len(message) - 1) + (len(message) * 8).to_bytes(8, "big")
    target = hashlib.sha256(message).digest()
    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            target.hex(),
            "--message-length",
            str(len(message)),
            "--known-message",
            message.hex(),
            "--block",
            block.hex(),
            "--reverse-to-round",
            "32",
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    boundary = result["known_block_round_boundary"]
    assert boundary["forward_feed_verified"] is True
    assert boundary["state_after_round"] == 32
    assert len(boundary["state_words"]) == 8


@pytest.mark.parametrize("unknown_index", [0, 1, 2])
@pytest.mark.parametrize("first", [0, 1])
@pytest.mark.parametrize("second", [0, 1])
@pytest.mark.parametrize("unknown", [0, 1])
def test_majority_inverse_matches_single_bit_truth_table(
    unknown_index: int,
    first: int,
    second: int,
    unknown: int,
) -> None:
    known_values = iter((first, second))
    values: list[int | None] = [
        None if index == unknown_index else next(known_values)
        for index in range(3)
    ]
    output = int(first + second + unknown >= 2)

    result = invert_majority_word(output, *values)

    if first == second:
        assert result.recovered_word == 0
        assert result.determined_mask == 0
        assert result.ambiguous_mask == 0xFFFFFFFF
        assert result.fully_determined is False
    else:
        assert result.recovered_word == unknown
        assert result.determined_mask == 1
        assert result.ambiguous_mask == 0xFFFFFFFE


def test_majority_inverse_recovers_determined_bits_and_preserves_ambiguity() -> None:
    known_a = 0xAAAA5555
    known_b = 0x5555AAAA
    unknown = 0x12345678

    result = invert_majority_word(unknown, known_a, known_b, None)

    assert result.recovered_word == unknown
    assert result.determined_mask == 0xFFFFFFFF
    assert result.ambiguous_mask == 0
    assert result.fully_determined is True

    ambiguous = invert_majority_word(0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, None)
    assert ambiguous.recovered_word == 0
    assert ambiguous.determined_mask == 0
    assert ambiguous.ambiguous_mask == 0xFFFFFFFF


def test_majority_inverse_rejects_conflicting_or_invalid_words() -> None:
    with pytest.raises(ValueError, match="conflicts"):
        invert_majority_word(1, 0, 0, None)
    with pytest.raises(ValueError, match="exactly one"):
        invert_majority_word(0, 0, 0, 0)
    with pytest.raises(ValueError, match="32-bit"):
        invert_majority_word(0x100000000, 0, 1, None)


def test_sha256_majority_inverse_cli_reports_ambiguous_bits(capsys) -> None:
    assert main(
        [
            "sha256-maj-invert",
            "--output",
            "0x00000000",
            "--a",
            "0",
            "--b",
            "0",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["fully_determined"] is False
    assert output["ambiguous_mask"] == "0xffffffff"


@pytest.mark.parametrize("unknown_mask", range(1, 8))
@pytest.mark.parametrize("e_bit,f_bit,g_bit", [(e, f, g) for e in (0, 1) for f in (0, 1) for g in (0, 1)])
def test_choice_inverse_exhaustively_matches_single_bit_truth_table(
    unknown_mask: int,
    e_bit: int,
    f_bit: int,
    g_bit: int,
) -> None:
    actual = (e_bit, f_bit, g_bit)
    output_bit = (e_bit & f_bit) | ((1 - e_bit) & g_bit)
    known = tuple(
        None if unknown_mask & (1 << index) else (0xFFFFFFFF if value else 0)
        for index, value in enumerate(actual)
    )

    result = invert_choice_words(
        0xFFFFFFFF if output_bit else 0,
        *known,
    )

    for index, recovered in enumerate((result.e, result.f, result.g)):
        if not unknown_mask & (1 << index):
            assert recovered is None
            continue
        assert recovered is not None
        missing = [i for i in range(3) if unknown_mask & (1 << i)]
        candidates = []
        for candidate in range(1 << len(missing)):
            completion = list(actual)
            for offset, missing_index in enumerate(missing):
                completion[missing_index] = (candidate >> offset) & 1
            if (completion[0] & completion[1]) | ((1 - completion[0]) & completion[2]) == output_bit:
                candidates.append(completion[index])
        expected_determined = len(set(candidates)) == 1
        expected_word = 0xFFFFFFFF if expected_determined and candidates[0] else 0
        assert recovered.recovered_word == expected_word
        assert recovered.determined_mask == (0xFFFFFFFF if expected_determined else 0)
        assert recovered.determined_mask | recovered.ambiguous_mask == 0xFFFFFFFF
        assert recovered.determined_mask & recovered.ambiguous_mask == 0
    assert result.fully_determined == all(
        operand is None or operand.fully_determined
        for operand in (result.e, result.f, result.g)
    )


def test_choice_inverse_recovers_selector_and_reports_ambiguous_data_bits() -> None:
    selector = 0x01234567
    recovered_selector = invert_choice_words(selector, None, 0xFFFFFFFF, 0)
    assert recovered_selector.e is not None
    assert recovered_selector.e.recovered_word == selector
    assert recovered_selector.e.determined_mask == 0xFFFFFFFF
    assert recovered_selector.fully_determined is True

    recovered_f = invert_choice_words(0xAAAAAAAA, 0, None, 0xAAAAAAAA)
    assert recovered_f.f is not None
    assert recovered_f.f.recovered_word == 0
    assert recovered_f.f.determined_mask == 0
    assert recovered_f.f.ambiguous_mask == 0xFFFFFFFF
    assert recovered_f.fully_determined is False


@pytest.mark.parametrize("unknown_mask", range(1, 8))
def test_choice_inverse_matches_bitwise_oracle_for_mixed_word_bits(unknown_mask: int) -> None:
    actual = (0xA53C96E1, 0xC39A5F07, 0x3C65A0F8)
    output = (actual[0] & actual[1]) | (~actual[0] & actual[2])
    known = tuple(
        None if unknown_mask & (1 << index) else value
        for index, value in enumerate(actual)
    )
    result = invert_choice_words(output, *known)

    for operand_index, recovered in enumerate((result.e, result.f, result.g)):
        if not unknown_mask & (1 << operand_index):
            assert recovered is None
            continue
        assert recovered is not None
        expected_word = 0
        expected_determined_mask = 0
        missing = [i for i in range(3) if unknown_mask & (1 << i)]
        for bit_index in range(32):
            target_bit = (output >> bit_index) & 1
            possible: set[int] = set()
            for candidate in range(1 << len(missing)):
                completion = [
                    (value >> bit_index) & 1
                    for value in actual
                ]
                for offset, index in enumerate(missing):
                    completion[index] = (candidate >> offset) & 1
                if (
                    (completion[0] & completion[1])
                    | ((1 - completion[0]) & completion[2])
                ) == target_bit:
                    possible.add(completion[operand_index])
            if len(possible) == 1:
                expected_determined_mask |= 1 << bit_index
                if 1 in possible:
                    expected_word |= 1 << bit_index
        assert recovered.recovered_word == expected_word
        assert recovered.determined_mask == expected_determined_mask
        assert recovered.ambiguous_mask == (0xFFFFFFFF ^ expected_determined_mask)


def test_choice_inverse_rejects_conflicts_invalid_words_and_no_unknowns() -> None:
    with pytest.raises(ValueError, match="conflicts"):
        invert_choice_words(1, 0, None, 0)
    with pytest.raises(ValueError, match="unknown"):
        invert_choice_words(0, 0, 0, 0)
    with pytest.raises(ValueError, match="32-bit"):
        invert_choice_words(0, 0x100000000, None, 0)


def test_sha256_choice_inverse_cli_reports_recovered_input(capsys) -> None:
    assert main(
        [
            "sha256-ch-invert",
            "--output",
            "0x01234567",
            "--f",
            "0xffffffff",
            "--g",
            "0",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "sha256-choice-input-inversion"
    assert output["inputs"]["e"]["recovered_word"] == "0x01234567"
    assert output["fully_determined"] is True


@pytest.mark.parametrize("length", [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024])
def test_sha256_full_rounds_match_hashlib(length: int) -> None:
    data = bytes(range(256))[:length] if length <= 256 else bytes(range(256)) * (length // 256)
    assert sha256_reduced(data, rounds=64) == hashlib.sha256(data).digest()


@pytest.mark.parametrize(
    ("rounds", "expected"),
    [
        (1, "f39c5e57589de1065aa1e70e5ca5ed16d368487360adf92662b1ff2e64b60536"),
        (16, "4d26ecc81603720fd77d64679a649114062435aa8f640c47b4cb816dc73cb464"),
        (17, "c952f2b04e28efcc17057513d87f676b2a137f46072638ae90660f4bb5cd8471"),
        (32, "645fb8c1b27b5ad6dd3d597ce12fe2657bad056d2eecf5fb1e07c414a81f6827"),
        (64, "ce4f90599ffb5acb79da9099e1f8185d958c5e0d9edfbb68939409b9872b43e5"),
    ],
)
def test_sha256_compression_matches_reference_vectors(rounds: int, expected: str) -> None:
    state = tuple((index * 0x01020304 + 0xABCDEF01) & 0xFFFFFFFF for index in range(8))
    compressed = _sha_compress(bytes(range(64)), state, rounds)

    assert b"".join(word.to_bytes(4, "big") for word in compressed) == bytes.fromhex(expected)


@pytest.mark.parametrize("rounds", [1, 15, 16, 17, 24, 32, 64])
def test_sha256_reduced_rounds_return_digest(rounds: int) -> None:
    digest = sha256_reduced(bytes(range(65)), rounds=rounds)
    assert len(digest) == hashlib.sha256().digest_size


@pytest.mark.parametrize("rounds", [0, 65])
def test_sha256_reduced_rejects_invalid_round_count(rounds: int) -> None:
    with pytest.raises(ValueError, match="rounds must be between 1 and 64"):
        sha256_reduced(b"data", rounds=rounds)


@pytest.mark.parametrize("length", [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024])
@pytest.mark.parametrize("rounds", [1, 16, 32, 63, 64])
def test_sha256_stream_matches_bytes_api_with_irregular_chunks(length: int, rounds: int) -> None:
    data = bytes(index % 256 for index in range(length))
    chunks = (data[start : start + 7] for start in range(0, length, 7))

    assert sha256_reduced_stream(chunks, rounds=rounds) == sha256_reduced(data, rounds=rounds)


@pytest.mark.parametrize("rounds", [1, 32, 64])
def test_sha256_stream_reads_binary_file_objects(rounds: int) -> None:
    data = bytes(range(256)) * 2 + b"tail"
    assert sha256_reduced_stream(BytesIO(data), rounds=rounds) == sha256_reduced(data, rounds=rounds)


def test_sha256_stream_rejects_non_byte_chunks() -> None:
    with pytest.raises(TypeError, match="input chunks must be bytes"):
        sha256_reduced_stream([b"valid", "not bytes"])  # type: ignore[list-item]


def test_sha256_stream_cli_processes_binary_file(tmp_path, capsys) -> None:
    data = bytes(range(256)) * 3 + b"tail"
    input_path = tmp_path / "message.bin"
    input_path.write_bytes(data)

    assert main(["sha256-stream", "--input", str(input_path), "--rounds", "64"]) == 0
    assert capsys.readouterr().out.strip() == hashlib.sha256(data).hexdigest()


def test_sha256_backward_trace_matches_supplied_numeric_ledger() -> None:
    target = bytes.fromhex(
        "5f764e2e697337ae70aa6f2c32101f3ce3a738842620f469d8c5cf573342d460"
    )

    trace = sha256_backward_trace(target)

    assert trace.working_state == (
        0xF56C67C7,
        0xAE0B8929,
        0x343B7BBA,
        0x8CC02A02,
        0x9298E605,
        0x8B1B8BDD,
        0xB941F5AC,
        0xD7620747,
    )
    assert [
        (step.round_index, step.t1, step.t2, step.recovered_a_index, step.recovered_a)
        for step in trace.steps
    ] == [
        (63, 0x3C7607EF, 0xB8F65FD8, 60, 0x5622DE16),
        (62, 0xDCB77732, 0xD15411F7, 59, 0xAE6414AB),
        (61, 0xB24EF706, 0x81EC84B4, 58, 0x06F2FEA6),
        (60, 0x981AEB91, 0xF4A53E71, 57, 0x3F471BB6),
    ]
    assert (trace.boundary_round, trace.boundary_a_index, trace.boundary_t1) == (
        59,
        56,
        0x4925E6BD,
    )
    assert (trace.bridge_h_index, trace.bridge_w_index, trace.bridge_h_offset) == (
        63,
        63,
        0x184A25D4,
    )


@pytest.mark.parametrize(
    ("target", "rounds", "message_length"),
    [(bytes(31), 64, 33), (bytes(32), 7, 33), (bytes(32), 64, 56)],
)
def test_sha256_backward_trace_cli_rejects_unsupported_scope(
    target: bytes, rounds: int, message_length: int
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "sha256-backward-ledger",
                "--target",
                target.hex(),
                "--rounds",
                str(rounds),
                "--message-length",
                str(message_length),
            ]
        )
    assert exc_info.value.code == 2


def test_sha256_backward_trace_cli_marks_unresolved_boundary(capsys) -> None:
    target = bytes.fromhex(
        "5f764e2e697337ae70aa6f2c32101f3ce3a738842620f469d8c5cf573342d460"
    )

    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            target.hex(),
            "--message-length",
            "33",
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["candidate_recovered"] is False
    assert result["numerically_recovered_a_words"]["a57"] == "3f471bb6"
    assert result["first_unresolved_boundary"]["equation"] == (
        "a56 = e60 - T1_59 (mod 2**32)"
    )
    assert result["two_line_underdetermination"]["final_round_h_line_equation"] == (
        "h63 = 0x184a25d4 - W63 (mod 2**32)"
    )
    assert "does not establish a direct W63-to-e60 identity" in result[
        "two_line_underdetermination"
    ]["description"]
    assert result["interpretation"]["reported_stage4_timeout"]["status"] == "UNKNOWN"
    assert result["interpretation"]["reported_stage4_timeout"]["reported_variables"] == 100768
    assert result["verdict"] == "experimental algebraic evidence, not a SHA-256 break"
    assert result["state_classification"]["numerically_recovered"]["a57"] == "3f471bb6"
    assert result["state_classification"]["symbolically_determined"][0]["variable"] == "a56"
    assert "e60" in result["state_classification"]["still_unresolved"]
    assert result["interpretation"]["external_stage4_artifacts_loaded"] is False
    assert result["candidate_recovered"] is False


def test_sha256_backward_trace_cli_can_save_ledger(tmp_path, capsys) -> None:
    target = bytes.fromhex(
        "5f764e2e697337ae70aa6f2c32101f3ce3a738842620f469d8c5cf573342d460"
    )
    output_path = tmp_path / "backward-ledger.json"

    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            target.hex(),
            "--message-length",
            "33",
            "--output",
            str(output_path),
        ]
    ) == 0

    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["candidate_recovered"] is False
    assert "Backward trace written to" in capsys.readouterr().err


def test_sha256_backward_ledger_checks_known_message_h_w_relation(capsys) -> None:
    message = bytes(range(33))
    target = hashlib.sha256(message).digest()

    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            target.hex(),
            "--message-length",
            str(len(message)),
            "--known-message",
            message.hex(),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    bridge = result["two_line_underdetermination"]["known_message_check"]
    assert bridge["known_message_target_matches"] is True
    assert bridge["known_message_word_value"] == "f21892fa"
    assert bridge["derived_state_values"]["h63"] == 0x11EEFB1A


def test_sha256_schedule_dependency_graph_evaluates_known_one_block_message(capsys) -> None:
    nodes = sha256_schedule_dependencies()
    node_by_index = {node.word_index: node for node in nodes}
    message = b"abc"
    target = hashlib.sha256(message).digest()

    assert node_by_index[15].operation == "input_word"
    assert node_by_index[63].dependencies == (
        "sigma1(W61)",
        "W56",
        "sigma0(W48)",
        "W47",
    )
    assert len(sha256_schedule_words(b"abc\x80" + bytes(52) + bytes(7) + b"\x18")) == 64

    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            target.hex(),
            "--message-length",
            str(len(message)),
            "--known-message",
            message.hex(),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    graph = result["schedule_dependency_graph"]
    assert graph["known_message_target_matches"] is True
    assert graph["evaluated_words"]["W0"] == "61626380"
    assert graph["evaluated_words"]["W15"] == "00000018"
    assert graph["word_dependencies"][-1]["word"] == "W63"
    assert result["round_boundary_dependencies"]["round_expression_unresolved_inputs"] == [
        "h59",
        "e59",
        "f59",
        "g59",
        "W59",
    ]
    assert "does not establish an algebraic dependency" in result[
        "round_boundary_dependencies"
    ]["warning"]


def test_sha256_schedule_cli_reports_known_message_target_mismatch(capsys) -> None:
    message = b"abc"
    wrong_target = bytes(32)

    assert main(
        [
            "sha256-backward-ledger",
            "--target",
            wrong_target.hex(),
            "--message-length",
            str(len(message)),
            "--known-message",
            message.hex(),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["schedule_dependency_graph"]["known_message_target_matches"] is False
