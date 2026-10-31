"""Check the official test-vector fixtures against their pinned provenance.

Usage::

    python scripts/vectors.py verify   # offline: local checksums match tests/vectors/SOURCES.json
    python scripts/vectors.py fetch    # online: re-download each source at its pinned commit

``verify`` runs in the test suite (tests/test_vector_provenance.py). ``fetch``
is for maintainers refreshing or auditing fixtures: it checks every source's
checksum at the pinned commit, that verbatim copies are byte-identical, and that
the BIP-39 subset equals the source's English vectors. To move to a newer BIP
revision, update the commit and checksums in SOURCES.json in the same change
that updates the fixture; never edit expected values by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

VECTOR_DIR = Path(__file__).resolve().parent.parent / "tests" / "vectors"
MANIFEST = VECTOR_DIR / "SOURCES.json"
UNLISTED = {"README.md", "SOURCES.json"}


def normalized_sha256(data: bytes) -> str:
    """Hash with CRLF normalised to LF, so Windows checkouts hash like Linux ones."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict[str, dict]:
    return json.loads(path.read_text(encoding="utf-8"))["files"]


def verify(vector_dir: Path = VECTOR_DIR, manifest: Path = MANIFEST) -> list[str]:
    """Return a list of problems; empty when every fixture matches its pinned checksum."""
    files = load_manifest(manifest)
    problems = []
    present = {p.name for p in vector_dir.iterdir() if p.is_file()} - UNLISTED
    for name in sorted(present - set(files)):
        problems.append(f"{name}: fixture has no provenance entry in SOURCES.json")
    for name, entry in sorted(files.items()):
        path = vector_dir / name
        if not path.is_file():
            problems.append(f"{name}: listed in SOURCES.json but missing")
            continue
        actual = normalized_sha256(path.read_bytes())
        if actual != entry["sha256"]:
            problems.append(f"{name}: sha256 {actual} != pinned {entry['sha256']}")
        for source in entry["sources"]:
            if len(source["commit"]) != 40:
                problems.append(f"{name}: source {source['path']} is not pinned to a full commit SHA")
    return problems


def _download(repo: str, commit: str, path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def fetch(vector_dir: Path = VECTOR_DIR, manifest: Path = MANIFEST) -> list[str]:
    """Re-download every source at its pinned commit and compare; return problems."""
    problems = []
    for name, entry in sorted(load_manifest(manifest).items()):
        local = (vector_dir / name).read_bytes()
        for source in entry["sources"]:
            label = f"{name} <- {source['repo']}:{source['path']}@{source['commit'][:12]}"
            data = _download(source["repo"], source["commit"], source["path"])
            if normalized_sha256(data) != source["sha256"]:
                problems.append(f"{label}: source checksum differs from SOURCES.json")
            elif source["mode"] == "verbatim" and normalized_sha256(local) != source["sha256"]:
                problems.append(f"{label}: local copy is not byte-identical to the source")
            elif source["mode"] == "subset" and (
                json.loads(local)["english"] != json.loads(data)["english"]
            ):
                problems.append(f"{label}: English vectors differ from the source")
            print(f"checked {label} ({source['mode']})")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("verify", "fetch"))
    args = parser.parse_args(argv)
    problems = verify() if args.command == "verify" else fetch()
    for problem in problems:
        print(f"FAIL: {problem}")
    if not problems:
        print(f"{args.command}: all {len(load_manifest())} fixtures match their pinned provenance")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
