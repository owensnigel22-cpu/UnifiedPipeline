"""RIPEMD-160 / HASH160 backend with an optional, self-verified native accelerator.

Bulk ``HASH160 = RIPEMD160(SHA256(pubkey))`` is the hot loop of address
generation. This module provides one small abstraction over it:

* :class:`Ripemd160Backend` defaults to KeyLab's pure-Python RIPEMD-160
  (:func:`keylab.hashes.reduced.ripemd160`) and works with no extra install.
* If a compiled shared library (``.dll`` / ``.so`` / ``.dylib``) from a project
  such as `FrozenCryptoLibs <https://github.com/FrozenCryptoLibs>`_ or
  `ecloop <https://github.com/vladkens/ecloop>`_ is present on the project path
  (or named by ``$KEYLAB_RIPEMD160_LIB``), it is loaded via :mod:`ctypes` and
  used **only if it reproduces the standard RIPEMD-160 test vectors** at load
  time. A library that is absent, unloadable, exports no matching symbol, or
  returns a wrong digest is rejected and the pure-Python path is used instead —
  so a mismatched ABI can never silently corrupt an address.
* :func:`batch_hash160` emulates the batch/SIMD throughput of tools like
  ``ripemd160mb`` by fanning a large pubkey list across a
  :class:`concurrent.futures.ProcessPoolExecutor`; each worker builds its own
  backend (a ctypes handle does not pickle).

These native libraries are **strictly optional accelerators**; none is a
dependency and none is bundled. The expected C ABI for an accepted symbol is
``void SYMBOL(const uint8_t *msg, size_t len, uint8_t out[20])`` for one of the
symbol names in :data:`_NATIVE_SYMBOLS`.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from keylab.hashes.reduced import ripemd160

__all__ = [
    "Ripemd160Backend",
    "batch_hash160",
    "default_backend",
    "hash160",
    "ripemd160",
]

# (input, expected RIPEMD-160 digest) — the published RIPEMD-160 test vectors.
_RIPEMD160_VECTORS: tuple[tuple[bytes, str], ...] = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
)

_NATIVE_SYMBOLS: tuple[str, ...] = ("ripemd160", "rmd160", "RIPEMD160")
_LIBRARY_STEMS: tuple[str, ...] = (
    "frozencryptolibs",
    "frozencrypto",
    "ecloop",
    "ripemd160",
    "rmd160",
)
_LIBRARY_SUFFIXES: tuple[str, ...] = (".dll", ".so", ".dylib")
_NativeFn = Callable[[bytes], bytes]


def _candidate_library_paths() -> list[Path]:
    """Yield plausible native-library paths on the project path, most specific first."""
    candidates: list[Path] = []
    override = os.environ.get("KEYLAB_RIPEMD160_LIB")
    if override:
        candidates.append(Path(override))
    search_dirs = [Path.cwd(), Path.cwd() / "lib", Path.cwd() / "native", Path(__file__).resolve().parent]
    seen: set[Path] = set()
    for directory in search_dirs:
        if directory in seen or not directory.is_dir():
            continue
        seen.add(directory)
        for stem in _LIBRARY_STEMS:
            for suffix in _LIBRARY_SUFFIXES:
                for name in (f"{stem}{suffix}", f"lib{stem}{suffix}"):
                    path = directory / name
                    if path.is_file():
                        candidates.append(path)
    return candidates


def _bind_native(library: ctypes.CDLL) -> _NativeFn | None:
    """Bind the first RIPEMD-160 symbol the library exports, or return None."""
    for symbol in _NATIVE_SYMBOLS:
        try:
            function = getattr(library, symbol)
        except AttributeError:
            continue
        function.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        function.restype = None

        def call(data: bytes, _function: Callable[..., object] = function) -> bytes:
            out = (ctypes.c_ubyte * 20)()
            length = len(data)
            buffer = (ctypes.c_ubyte * length).from_buffer_copy(data) if length else (ctypes.c_ubyte * 1)()
            _function(buffer, length, out)
            return bytes(out)

        return call
    return None


def _native_passes_self_test(native: _NativeFn) -> bool:
    """A native backend is trusted only if it reproduces every known vector."""
    try:
        return all(native(message).hex() == expected for message, expected in _RIPEMD160_VECTORS)
    except Exception:  # noqa: BLE001 — any ctypes/ABI failure disqualifies the native path
        return False


def _load_native(library_path: str | os.PathLike[str] | None = None) -> tuple[_NativeFn | None, str]:
    """Attempt to load and self-verify a native RIPEMD-160; fall back silently.

    Returns ``(callable_or_None, source_label)``.
    """
    paths = [Path(library_path)] if library_path is not None else _candidate_library_paths()
    for path in paths:
        try:
            library = ctypes.CDLL(str(path))
        except OSError:
            continue
        native = _bind_native(library)
        if native is not None and _native_passes_self_test(native):
            return native, f"native:{path.name}"
    return None, "python"


class Ripemd160Backend:
    """RIPEMD-160 / HASH160, using a verified native library when one is available.

    By default this discovers a native accelerator on the project path and uses
    it only if it passes the RIPEMD-160 self-test; otherwise it uses the
    pure-Python implementation. Pass ``prefer_native=False`` to force pure Python,
    or ``library_path`` to point at a specific shared library.
    """

    def __init__(
        self,
        *,
        prefer_native: bool = True,
        library_path: str | os.PathLike[str] | None = None,
    ) -> None:
        if prefer_native:
            native, source = _load_native(library_path)
        else:
            native, source = None, "python"
        self._native = native
        self._source = source

    @property
    def name(self) -> str:
        """``"python"`` or ``"native:<filename>"`` — which implementation is active."""
        return self._source

    @property
    def is_native(self) -> bool:
        """Whether a verified native accelerator is in use."""
        return self._native is not None

    def ripemd160(self, data: bytes) -> bytes:
        """Return RIPEMD-160(data)."""
        if self._native is not None:
            return self._native(bytes(data))
        return ripemd160(bytes(data))

    def hash160(self, data: bytes) -> bytes:
        """Return HASH160(data) = RIPEMD-160(SHA-256(data))."""
        return self.ripemd160(hashlib.sha256(bytes(data)).digest())


# A module-level default backend, discovered once, for the common single-call path.
_DEFAULT_BACKEND: Ripemd160Backend | None = None


def default_backend() -> Ripemd160Backend:
    """Return a shared, lazily-discovered default backend."""
    global _DEFAULT_BACKEND
    if _DEFAULT_BACKEND is None:
        _DEFAULT_BACKEND = Ripemd160Backend()
    return _DEFAULT_BACKEND


def hash160(data: bytes) -> bytes:
    """Return HASH160(data) using the shared default backend."""
    return default_backend().hash160(data)


# --- bulk HASH160 ----------------------------------------------------------

# A per-process backend so ProcessPoolExecutor workers do not re-discover per call.
_WORKER_BACKEND: Ripemd160Backend | None = None


def _worker_hash160(chunk: Sequence[bytes]) -> list[bytes]:
    global _WORKER_BACKEND
    if _WORKER_BACKEND is None:
        _WORKER_BACKEND = Ripemd160Backend()
    backend = _WORKER_BACKEND
    return [backend.hash160(pubkey) for pubkey in chunk]


def batch_hash160(
    pubkeys: Sequence[bytes],
    *,
    use_processes: bool = True,
    max_workers: int | None = None,
    chunk_size: int | None = None,
    process_threshold: int = 2048,
) -> list[bytes]:
    """Compute HASH160 for many public keys, fanning large inputs across processes.

    For small inputs (or ``use_processes=False``, or ``max_workers=1``) this runs
    sequentially in the current process. For larger inputs it splits ``pubkeys``
    into chunks and maps them over a :class:`ProcessPoolExecutor`, which is how
    SIMD batch hashers like ``ripemd160mb`` reclaim throughput on bulk address
    generation. Output order matches input order.

    ``process_threshold`` is the minimum number of pubkeys before the process
    pool is used; below it the sequential path avoids pool startup cost.
    """
    items = list(pubkeys)
    if not items:
        return []

    sequential = (
        not use_processes
        or max_workers == 1
        or len(items) < max(process_threshold, 2)
    )
    if sequential:
        return _worker_hash160(items)

    workers = max_workers if max_workers is not None else (os.cpu_count() or 1)
    workers = max(1, workers)
    if chunk_size is None:
        chunk_size = max(1, (len(items) + workers - 1) // workers)
    chunks = [items[start : start + chunk_size] for start in range(0, len(items), chunk_size)]

    results: list[bytes] = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for chunk_result in executor.map(_worker_hash160, chunks):
            results.extend(chunk_result)
    return results
