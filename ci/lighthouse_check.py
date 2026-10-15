"""Fixed mobile/desktop score floors; missing categories never pass."""

import json
import sys
from pathlib import Path

FLOORS = {"performance": 0.90, "accessibility": 0.95, "best-practices": 0.95, "seo": 0.95}


def check(report):
    for name, floor in FLOORS.items():
        score = report.get("categories", {}).get(name, {}).get("score")
        if type(score) not in {int, float} or not floor <= score <= 1:
            raise ValueError("Lighthouse score floor or coverage failed")
    if report.get("runtimeError") or report.get("runWarnings"):
        raise ValueError("Lighthouse coverage incomplete")


if __name__ == "__main__":
    try:
        check(json.loads(Path(sys.argv[1]).read_bytes()))
    except (ValueError, OSError, IndexError):
        sys.stderr.write("FAIL Lighthouse coverage/floors\n")
        raise SystemExit(1) from None
