"""Generate and validate the root CycloneDX 1.6 cryptographic bill of materials."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "cbom-baseline.json"


def main() -> int:
    pqcheck = shutil.which("pqcheck")
    if pqcheck is None:
        raise SystemExit(
            "pqcheck is not installed; use Python 3.12+ and "
            "`python -m pip install -r requirements-cbom.txt`"
        )

    result = subprocess.run(
        [
            pqcheck,
            "scan",
            str(ROOT),
            "--format",
            "cbom",
            "--output",
            str(OUTPUT),
        ],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        return result.returncode

    try:
        document = json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"pqcheck did not produce valid JSON at {OUTPUT}: {exc}") from exc

    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise SystemExit(f"pqcheck output is not a CycloneDX 1.6 CBOM: {OUTPUT}")
    print(f"Generated and verified {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
