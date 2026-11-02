"""Generate docs/api.md from each module's ``__all__``, signatures, and docstrings.

Usage::

    python scripts/gen_api_docs.py          # rewrite docs/api.md
    python scripts/gen_api_docs.py --check  # exit 1 if docs/api.md is out of date

tests/test_api_docs.py runs the check, so a public-API change without a
regenerated reference fails the suite.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "api.md"

# (module, one-line description) in the order the reference presents them.
MODULES = (
    ("keylab.ec.secp256k1", "secp256k1 arithmetic, backends, ECDSA, shared curve helpers"),
    ("keylab.ec.sec1", "SEC1 and x-only public-key encodings"),
    ("keylab.ec.schnorr", "BIP-340 Schnorr signatures"),
    ("keylab.ec.musig2", "BIP-327 MuSig2 key aggregation"),
    ("keylab.ec.ecdsa_recovery", "ECDSA public-key recovery"),
    ("keylab.ec.reference", "Frozen textbook oracle for validating optimizations"),
    ("keylab.ec.validation", "Differential validation against the reference"),
    ("keylab.hd", "BIP-32/39/44/49/84/86 hierarchical deterministic keys"),
    ("keylab.mnemonic", "BIP-39 mnemonic generation, validation, seed derivation"),
    ("keylab.encoding.taproot", "BIP-341 Taproot outputs, script trees, key-path signing"),
    ("keylab.encoding.transaction", "Transaction parsing and BIP-341 / BIP-143 signature hashing"),
    ("keylab.encoding.address", "Address encoding and verification"),
    ("keylab.encoding.bech32", "BIP-173 Bech32 / BIP-350 Bech32m"),
    ("keylab.encoding.base58", "Base58 and Base58Check"),
    ("keylab.encoding.wif", "Wallet Import Format"),
    ("keylab.hashes.tagged", "BIP-340 tagged hashing"),
    ("keylab.ec.division_polynomials", "Research: division polynomials over F_p"),
    ("keylab.ec.quartic", "Research: doubling-quartic inversion"),
    ("keylab.ec.halving", "Research: point halving"),
    ("keylab.benchmarks", "Benchmarks"),
)

HEADER = """# API reference

Public API of the cryptographic modules, generated from each module's
`__all__`, signatures, and docstrings (regenerate after API changes rather
than editing by hand). Everything here is research/teaching code; read
[SECURITY.md](../SECURITY.md) before handling any real key.

CLI commands are listed by `keylab --help` and `keylab-advanced --help`;
[architecture.md](architecture.md) explains how the modules fit together.
"""

STABILITY = """## API stability

- **Public API.** A name is public if it is listed in its module's `__all__`
  (and therefore in this reference). Names starting with `_`, and modules or
  names not listed here, are internal and may change in any release.
- **Package re-exports.** `keylab.ec` re-exports the most used curve,
  signature, and MuSig2 names; `from keylab.ec import ...` and the full module
  path refer to the same objects.
- **Before 1.0.** KeyLab follows semantic versioning with the 0.x convention:
  a minor release (0.2 → 0.3) may change public behaviour, and every such
  change is listed under **Changed** in [CHANGELOG.md](../CHANGELOG.md). Patch
  releases (0.2.x) only fix bugs.
- **Never stable.** Benchmark report fields and teaching-trace output
  (`keylab-advanced`) are for reading, not parsing.
"""

_MAX_VALUE_REPR = 40


def _anchor(module: str) -> str:
    return module.replace(".", "")


def _public_names(module) -> list[str]:
    names = getattr(module, "__all__", None)
    if names is None:
        names = [
            name for name, value in vars(module).items()
            if not name.startswith("_") and getattr(value, "__module__", None) == module.__name__
        ]
    return sorted(names, key=str.lower)


def _is_type_alias(value: object) -> bool:
    # inspect.signature of a builtin like list differs between Python versions.
    return isinstance(value, (types.GenericAlias, types.UnionType))


def _signature(name: str, value: object) -> str:
    if _is_type_alias(value):
        return f"{name} = {value!r}"
    if inspect.isclass(value):
        try:
            return f"class {name}{inspect.signature(value)}"
        except (TypeError, ValueError):
            return f"class {name}"
    if callable(value):
        return f"{name}{inspect.signature(value)}"
    text = repr(value)
    return f"{name} = {text if len(text) <= _MAX_VALUE_REPR else type(value).__name__}"


def _summary(value: object) -> str:
    if _is_type_alias(value) or not (inspect.isclass(value) or callable(value)):
        return ""
    doc = inspect.getdoc(value) or ""
    return doc.splitlines()[0].strip() if doc else ""


def _cell(text: str) -> str:
    return text.replace("||", "//").replace("|", "\\|")


def render() -> str:
    lines = [HEADER, "## Contents", ""]
    for module, description in MODULES:
        lines.append(f"- [`{module}`](#{_anchor(module)}) — {description}")
    lines += ["- [API stability](#api-stability)", ""]
    for module_name, description in MODULES:
        module = importlib.import_module(module_name)
        doc = (inspect.getdoc(module) or "").splitlines()
        lines += [f"## `{module_name}`", "", f"{description}.", ""]
        if doc:
            lines += [doc[0], ""]
        lines += ["| Name | Signature / value | Summary |", "|---|---|---|"]
        for name in _public_names(module):
            value = getattr(module, name)
            lines.append(f"| `{name}` | `{_cell(_signature(name, value))}` | {_cell(_summary(value))} |")
        lines.append("")
    lines.append(STABILITY)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if docs/api.md is stale")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8").replace("\r\n", "\n")
        if current != text:
            print("docs/api.md is out of date; run: python scripts/gen_api_docs.py")
            return 1
        print("docs/api.md is up to date")
        return 0
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
