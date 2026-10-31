"""docs/api.md matches the public API declared by each module's ``__all__``."""

from __future__ import annotations

import importlib

import pytest

from scripts import gen_api_docs


def test_api_reference_is_up_to_date() -> None:
    current = gen_api_docs.OUTPUT.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert current == gen_api_docs.render(), "run: python scripts/gen_api_docs.py"


@pytest.mark.parametrize("module_name", [name for name, _ in gen_api_docs.MODULES])
def test_documented_modules_declare_existing_public_names(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert isinstance(module.__all__, list)
    assert len(module.__all__) == len(set(module.__all__))
    assert [name for name in module.__all__ if not hasattr(module, name)] == []


def test_keylab_ec_reexports_are_the_module_objects() -> None:
    ec = importlib.import_module("keylab.ec")
    for name in ec.__all__:
        value = getattr(ec, name)
        home = importlib.import_module(getattr(value, "__module__", None) or "keylab.ec.secp256k1")
        if home.__name__.startswith("keylab.ec."):
            assert getattr(home, name) is value, name
