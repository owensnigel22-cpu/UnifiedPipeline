"""Cross-platform corpus smoke test (NOT fuzzing).

This runs the shared fuzz-target bodies (``fuzz.targets``) over the seed corpora
*without Atheris*, so the targets and seeds are exercised on every platform
(including Windows, where Atheris is unavailable). It is deliberately named
``corpus_smoke`` rather than ``fuzz`` and must not be counted as coverage-guided
fuzz coverage. It also enforces canary containment: the planted-bug module must
not be importable as part of ``keylab``.
"""

from __future__ import annotations

import importlib

import pytest

from fuzz import corpus_seed, targets

_TARGETS = ("psbt", "transaction", "bech32", "base58", "wif", "mnemonic")


@pytest.mark.parametrize("name", _TARGETS)
def test_every_seed_is_handled_without_unexpected_errors(name):
    """Each seed must pass through the shared target body raising only expected errors."""
    fn = targets.TARGETS[name]
    seeds = corpus_seed.seeds_for(name)
    assert seeds, f"no seeds generated for {name}"
    for seed in seeds:
        fn(seed)  # must not raise: expected parser errors are swallowed inside the body


@pytest.mark.parametrize("name", _TARGETS)
def test_target_body_handles_adversarial_bytes(name):
    """Near-valid and boundary mutations of each seed stay within expected errors."""
    fn = targets.TARGETS[name]
    for seed in corpus_seed.seeds_for(name):
        for mutated in (seed + b"\x00", seed[:-1] if seed else seed, b"\xff" + seed, seed * 2):
            fn(mutated)


def test_targets_and_entry_points_stay_in_sync():
    """Every shared target has a matching fuzz entry-point module name."""
    import pathlib
    fuzz_dir = pathlib.Path(targets.__file__).parent
    for name in targets.TARGETS:
        assert (fuzz_dir / f"fuzz_{name}.py").is_file(), f"missing fuzz_{name}.py"


def test_canary_is_not_importable_as_keylab():
    """The seeded-defect canary must never be shippable as a keylab submodule."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("keylab.fuzz_canary")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("keylab.fuzz")


def test_canary_bug_is_deterministic_and_obvious():
    """The canary must fail loudly (IndexError), not silently, on a crafted input."""
    from fuzz.fuzz_canary import buggy_parser

    assert buggy_parser(b"") == 0
    assert buggy_parser(b"\x02\x01\x01") == 2  # declared 2, body has 2 bytes: fine
    with pytest.raises(IndexError):
        buggy_parser(b"\x05\x01")  # declares 5, body has 1: out of bounds
