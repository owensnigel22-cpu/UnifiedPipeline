"""Run a command under a hard memory cap and wall-clock timeout, cross-platform.

On Windows a Job Object with ``ProcessMemoryLimit`` enforces the cap at allocation
time (the child's over-limit allocations fail, so it dies cleanly instead of
swapping until the host crashes). On POSIX the child sets ``RLIMIT_AS`` via a
preexec hook. Either way a breach is a clean non-zero exit, never a machine crash.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CappedResult:
    status: str  # "ok" | "memory" | "timeout" | "error"
    returncode: int | None
    stdout: str
    stderr: str


def _run_windows(argv, mem_bytes, timeout, input_text):
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("Read", "Write", "Other", "ReadT", "WriteT", "OtherT")]

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class EXT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9

    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = EXT()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    info.ProcessMemoryLimit = ctypes.c_size_t(mem_bytes)
    if not k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                       ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())

    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # assign immediately (targets do not allocate gigabytes in the first milliseconds)
    if not k32.AssignProcessToJobObject(job, int(proc._handle)):  # type: ignore[attr-defined]
        proc.kill()
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        out, err = proc.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return CappedResult("timeout", proc.returncode, out or "", err or "")
    finally:
        k32.CloseHandle(job)
    # a non-zero exit after an over-limit allocation reads as a clean memory kill
    status = "ok" if proc.returncode == 0 else "memory"
    return CappedResult(status, proc.returncode, out or "", err or "")


def _run_posix(argv, mem_bytes, timeout, input_text):
    import resource

    def _limit():
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

    try:
        proc = subprocess.run(argv, input=input_text, capture_output=True, text=True,
                              timeout=timeout, preexec_fn=_limit, check=False)
        return CappedResult("ok" if proc.returncode == 0 else "memory",
                            proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return CappedResult("timeout", None, exc.stdout or "", exc.stderr or "")


def run_capped(argv, *, mem_bytes: int, timeout: float, input_text: str | None = None) -> CappedResult:
    """Run ``argv`` with at most ``mem_bytes`` of memory and ``timeout`` seconds."""
    if sys.platform == "win32":
        return _run_windows(argv, mem_bytes, timeout, input_text)
    return _run_posix(argv, mem_bytes, timeout, input_text)


if __name__ == "__main__":
    # self-test: a child that tries to allocate ~2 GiB under a 400 MiB cap must die cleanly.
    hog = "b = bytearray(2*1024*1024*1024); print('ALLOCATED', len(b))"
    res = run_capped([sys.executable, "-c", hog], mem_bytes=400 * 1024 * 1024, timeout=60)
    print(f"status={res.status} rc={res.returncode}")
    print("stdout:", res.stdout.strip()[:200])
    print("stderr:", res.stderr.strip().splitlines()[-1] if res.stderr.strip() else "")
    print("PASS: capped cleanly" if res.status == "memory" and "ALLOCATED" not in res.stdout
          else "FAIL: allocation was not prevented")
