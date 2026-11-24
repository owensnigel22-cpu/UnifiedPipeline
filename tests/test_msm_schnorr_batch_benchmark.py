import hashlib
from importlib.util import find_spec

from keylab.ec.schnorr import (
    schnorr_public_key,
    schnorr_sign,
    schnorr_verify,
    schnorr_verify_batch,
)
from keylab.ec.secp256k1 import G, N, P, multi_scalar_mult
from scripts.benchmark_msm_schnorr_batch import (
    DEFAULT_SIZES,
    MSM_DISTRIBUTIONS,
    _corrupt_signature,
    _individual_results,
    _msm_expected,
    _msm_methods,
    _native_individual_setup,
    _native_individual_verify,
    _native_schnorr_preflight,
    _scenario_items,
    benchmark_verification_components,
    build_msm_corpora,
    build_schnorr_items,
)


def test_benchmark_default_sizes_include_256() -> None:
    assert DEFAULT_SIZES[-1] == 256
    corpora = build_msm_corpora(seed=51, max_size=256)
    assert len(corpora["random"]) == 256


def test_msm_benchmark_corpora_are_seeded_and_cover_requested_shapes() -> None:
    first = build_msm_corpora(seed=44, max_size=5)
    second = build_msm_corpora(seed=44, max_size=5)

    assert first == second
    assert tuple(first) == MSM_DISTRIBUTIONS
    assert any(scalar == 0 for scalar, _ in first["zero-heavy"][3][0])
    repeated_points = [point for _, point in first["repeated-points"][3][0]]
    assert len(set(repeated_points)) == 1
    assert any(point is None for _, point in first["mixed-points"][4][0])


def test_msm_benchmark_methods_match_independent_reference() -> None:
    corpora = build_msm_corpora(seed=45, max_size=2)
    for distribution in MSM_DISTRIBUTIONS:
        pairs, factors = corpora[distribution][1]
        expected = _msm_expected(pairs, factors)
        methods = _msm_methods(pairs, ())
        assert methods["naive-python"]() == expected
        assert methods["naive-python-glv"]() == expected
        assert methods["straus-glv-wnaf"]() == expected
        assert methods["pippenger-python"]() == expected
        assert methods["auto-python"]() == expected
        assert multi_scalar_mult(pairs, method="auto", backend="python-optimized") == expected


def test_msm_benchmark_infinity_and_optional_native_backends() -> None:
    assert multi_scalar_mult([(1, G), (N - 1, G)], method="straus") is None
    corpora = build_msm_corpora(seed=45, max_size=1)
    pairs, factors = corpora["random"][0]
    expected = _msm_expected(pairs, factors)
    native = [
        backend for backend in ("coincurve", "fastecdsa")
        if find_spec(backend) is not None
    ]
    for backend in native:
        method = _msm_methods(pairs, (backend,))[f"naive-{backend}"]
        assert method() == expected


def test_schnorr_benchmark_valid_scenarios_are_reproducible() -> None:
    items = build_schnorr_items(seed=46, count=4)
    assert items == build_schnorr_items(seed=46, count=4)
    assert [len(message) for message, _, _ in items] == [0, 1, 32, 100]
    assert all(_individual_results([item]) == [True] for item in items)
    assert schnorr_verify_batch(items, coefficients=[1, 2, 3, 4]) is True
    if find_spec("coincurve") is not None:
        from scripts.benchmark_msm_schnorr_batch import _native_schnorr_preflight

        assert _native_schnorr_preflight(items)["checked"] == len(items)


def test_schnorr_benchmark_invalid_positions_and_malformed_case() -> None:
    for size in (1, 2, 3, 4):
        for scenario in ("invalid-first", "invalid-middle", "invalid-last", "malformed-middle"):
            items, position, label = _scenario_items(seed=47, size=size, scenario=scenario)
            results = _individual_results(items)
            assert sum(not result for result in results) == 1
            assert position is not None and 0 <= position < size
            assert results[position] is False
            if size == 1:
                assert position == 0
                assert label == ("first" if scenario == "invalid-first"
                                 else "last" if scenario == "invalid-last"
                                 else "only")
            elif scenario.endswith("middle"):
                assert label == "middle"
                assert position == (1 if size == 2 else size // 2)
            else:
                assert label == ("first" if scenario == "invalid-first" else "last")

            coefficients = [1, *range(2, size + 1)]
            assert schnorr_verify_batch(items, coefficients=coefficients) is False


def test_schnorr_native_preflight_counts_valid_invalid_and_unsupported_separately() -> None:
    items = build_schnorr_items(seed=49, count=4)
    assert all(_individual_results([item]) == [True] for item in items)

    if find_spec("coincurve") is None:
        assert _native_schnorr_preflight(items) == {
            "available": False,
            "result": "not installed",
        }
        return

    native = _native_schnorr_preflight(items)
    assert native["available"] is True
    assert native["checked"] == len(items)
    assert not native["unsupported_or_parser_rejected"]

    corrupted = _corrupt_signature(items[0])
    native_invalid = _native_schnorr_preflight([corrupted])
    assert native_invalid["checked"] == 1

    malformed_signature = (items[0][0], items[0][1][:-1], items[0][2])
    native_unsupported = _native_schnorr_preflight([malformed_signature])
    assert native_unsupported["checked"] == 0
    assert native_unsupported["unsupported_or_parser_rejected"]


def test_native_individual_api_exists_but_native_batch_api_is_absent() -> None:
    if find_spec("coincurve") is None:
        return
    from coincurve import PublicKeyXOnly

    assert hasattr(PublicKeyXOnly, "verify")
    assert not any("batch" in name.lower() for name in dir(PublicKeyXOnly))

    items = build_schnorr_items(seed=50, count=4)
    keys, unsupported = _native_individual_setup(items)
    assert keys is not None
    assert unsupported == {}
    assert _native_individual_verify(items, keys) is True


def test_deterministic_benchmark_coefficients_obey_batch_contract() -> None:
    from scripts.benchmark_msm_schnorr_batch import _deterministic_coefficients

    coefficients = _deterministic_coefficients(48, 8)
    assert len(coefficients) == 8
    assert coefficients[0] == 1
    assert all(type(value) is int and 1 <= value < N for value in coefficients)
    assert coefficients == _deterministic_coefficients(48, 8)


def test_component_profile_reports_all_required_components() -> None:
    rows = benchmark_verification_components(
        seed=50,
        sizes=(1, 2),
        repetitions=2,
    )
    required = {
        "coefficient-generation",
        "signature-parsing",
        "public-key-parsing",
        "challenge-computation",
        "full-signature-and-point-parsing",
        "scalar-and-term-aggregation",
        "nonce-msm",
        "public-key-msm",
        "individual-end-to-end",
        "batch-csprng-end-to-end",
        "batch-fixed-coefficients-end-to-end",
        "native-public-key-parsing",
        "native-individual-verification",
    }
    assert {row["component"] for row in rows} == required
    assert all(row["fixture_construction_excluded"] is True for row in rows)
    assert all(row["repetitions"] == 2 for row in rows)


def _assert_complete_native_classification(items) -> dict:
    """Preflight raises on any native/Python disagreement; here we also require that
    every item is either a counted agreement or an explicitly classified unsupported
    input (a parser rejection is never silently counted as an agreement)."""
    preflight = _native_schnorr_preflight(items)
    if not preflight.get("available"):
        return preflight
    classified = preflight["checked"] + sum(preflight["unsupported_or_parser_rejected"].values())
    assert classified == len(items), (classified, len(items), preflight)
    return preflight


def test_differential_schnorr_input_categories_python_and_native() -> None:
    """Milestone 8 §5: Python individual vs Python batch vs native individual across
    the planned input categories. Python batch must equal the AND of the individual
    verifies; the native backend must never disagree on a parseable item; and every
    malformed/unsupported input must be classified, not counted as an agreement."""

    def _check(items, *, expect_batch, expect_individual) -> None:
        results = [schnorr_verify(message, signature, pk) for message, signature, pk in items]
        assert results == expect_individual
        # Fixed coefficients here are DIAGNOSTIC ONLY (never production batch verification).
        coefficients = [1, *range(2, len(items) + 1)] if items else None
        assert schnorr_verify_batch(items, coefficients=coefficients) is expect_batch
        _assert_complete_native_classification(items)

    # 1) Distinct valid public keys and messages (lengths 0, 1, 32, 100).
    valid = build_schnorr_items(seed=61, count=4)
    _check(valid, expect_batch=True, expect_individual=[True, True, True, True])

    # 2) Repeated public keys (one key, different messages), all valid.
    repeated_keys = build_schnorr_items(seed=62, count=4, repeated_key=True)
    assert len({pk for _, _, pk in repeated_keys}) == 1
    _check(repeated_keys, expect_batch=True, expect_individual=[True, True, True, True])

    # 3) Repeated message (one message, distinct keys), all valid.
    shared_message = b"m8-differential-shared-message"
    repeated_messages = []
    for index in range(4):
        private = int.from_bytes(hashlib.sha256(f"m8key{index}".encode()).digest(), "big") % (N - 1) + 1
        repeated_messages.append(
            (shared_message, schnorr_sign(shared_message, private, bytes(32)), schnorr_public_key(private))
        )
    assert len({pk for _, _, pk in repeated_messages}) == 4
    _check(repeated_messages, expect_batch=True, expect_individual=[True, True, True, True])

    # 4) Empty batch verifies as True (vacuous), and classifies nothing.
    assert schnorr_verify_batch([]) is True
    empty_preflight = _native_schnorr_preflight([])
    if empty_preflight.get("available"):
        assert empty_preflight["checked"] == 0

    # 5) Single-item batch equals the individual verify.
    _check([valid[0]], expect_batch=True, expect_individual=[True])

    # 6) Mixed valid and invalid (a corrupted but well-formed signature).
    mixed = list(valid)
    mixed[1] = _corrupt_signature(mixed[1])
    _check(mixed, expect_batch=False, expect_individual=[True, False, True, True])

    message, signature, public_key = valid[0]

    # 7) Out-of-range r (r == P): rejected by Python; native agrees it is invalid.
    out_of_range_r = [(message, P.to_bytes(32, "big") + signature[32:], public_key)]
    assert schnorr_verify(*out_of_range_r[0]) is False
    assert schnorr_verify_batch(out_of_range_r) is False
    _assert_complete_native_classification(out_of_range_r)

    # 8) Out-of-range s (s == N): rejected by Python; native agrees it is invalid.
    out_of_range_s = [(message, signature[:32] + N.to_bytes(32, "big"), public_key)]
    assert schnorr_verify(*out_of_range_s[0]) is False
    assert schnorr_verify_batch(out_of_range_s) is False
    _assert_complete_native_classification(out_of_range_s)

    # 9) Malformed signature length (63 bytes): Python rejects; native classifies it
    #    as unsupported (a parser rejection), never as an agreement.
    malformed_signature = [(message, signature[:-1], public_key)]
    assert schnorr_verify(*malformed_signature[0]) is False
    assert schnorr_verify_batch(malformed_signature) is False
    preflight = _native_schnorr_preflight(malformed_signature)
    if preflight.get("available"):
        assert preflight["checked"] == 0
        assert preflight["unsupported_or_parser_rejected"]

    # 10a) Malformed x-only public key length (31 bytes).
    malformed_pubkey = [(message, signature, public_key[:-1])]
    assert schnorr_verify(*malformed_pubkey[0]) is False
    assert schnorr_verify_batch(malformed_pubkey) is False
    preflight = _native_schnorr_preflight(malformed_pubkey)
    if preflight.get("available"):
        assert preflight["checked"] == 0
        assert preflight["unsupported_or_parser_rejected"]

    # 10b) Non-liftable / out-of-field x-only key (x == 0xff..ff > P).
    non_liftable = [(message, signature, b"\xff" * 32)]
    assert schnorr_verify(*non_liftable[0]) is False
    assert schnorr_verify_batch(non_liftable) is False
    _assert_complete_native_classification(non_liftable)
