"""Official-vector fixtures match the checksums pinned in tests/vectors/SOURCES.json."""

from __future__ import annotations

import json
import shutil

from scripts import vectors


def test_every_fixture_matches_its_pinned_provenance() -> None:
    assert vectors.verify() == []


def test_every_source_is_pinned_to_a_commit_with_a_known_mode() -> None:
    for name, entry in vectors.load_manifest().items():
        assert entry["sources"], name
        for source in entry["sources"]:
            assert len(source["commit"]) == 40, (name, source)
            assert source["mode"] in {"verbatim", "subset", "extracted"}, (name, source)


def test_verify_reports_an_edited_fixture(tmp_path) -> None:
    for path in vectors.VECTOR_DIR.iterdir():
        shutil.copy(path, tmp_path / path.name)
    edited = tmp_path / "bip340_test_vectors.csv"
    edited.write_bytes(edited.read_bytes() + b"\n")

    problems = vectors.verify(tmp_path, tmp_path / "SOURCES.json")

    assert len(problems) == 1 and problems[0].startswith("bip340_test_vectors.csv: sha256")


def test_verify_reports_an_unlisted_fixture(tmp_path) -> None:
    for path in vectors.VECTOR_DIR.iterdir():
        shutil.copy(path, tmp_path / path.name)
    (tmp_path / "new_vectors.json").write_text(json.dumps([]), encoding="utf-8")

    assert vectors.verify(tmp_path, tmp_path / "SOURCES.json") == [
        "new_vectors.json: fixture has no provenance entry in SOURCES.json"
    ]


def test_checksum_ignores_line_endings() -> None:
    assert vectors.normalized_sha256(b"a\r\nb\n") == vectors.normalized_sha256(b"a\nb\n")
