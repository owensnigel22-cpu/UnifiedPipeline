"""Coverage-guided fuzzing harness for KeyLab's untrusted-input parsers.

This package is test/CI tooling only. It is **not** part of the importable
``keylab`` library, is excluded from the sdist/wheel, and adds no runtime
dependency. The coverage-guided campaigns run under Atheris (Linux CI); the pure
shared target bodies in :mod:`fuzz.targets` also run without Atheris via
``tests/test_corpus_smoke.py`` so the targets are exercised on every platform.
"""
