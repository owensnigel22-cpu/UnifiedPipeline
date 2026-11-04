"""Seeded-defect canary: proves the harness actually catches a planted bug.

The buggy toy parser below lives **only** here, never in ``src/keylab``. It
reads a 1-byte length then indexes that many bytes without bounds-checking, so a
length byte larger than the remaining buffer raises a deterministic, obvious
``IndexError`` -- which a short Atheris campaign must discover. CI asserts the
canary campaign fails (non-zero exit / crash artifact); if it ever passes, the
fuzz harness is not wired correctly and the milestone gate blocks.

``buggy_parser`` and ``TestOneInput`` import without Atheris so the cross-platform
corpus smoke test can assert the bug is deterministic; Atheris is imported only
when the module is run as a campaign entry point.
"""


def buggy_parser(data: bytes) -> int:
    """Deliberately out-of-bounds: trusts a length byte it never validates."""
    if not data:
        return 0
    declared = data[0]
    body = data[1:]
    total = 0
    for i in range(declared):      # BUG: no check that declared <= len(body)
        total += body[i]           # IndexError when declared > len(body)
    return total


def TestOneInput(data: bytes) -> None:
    buggy_parser(data)


if __name__ == "__main__":
    import sys

    import atheris  # type: ignore

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
