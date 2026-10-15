"""Bounded owner-only entrypoint for the same Node browser checks used in CI."""

import os
import runpy
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def bounded_main():
    if os.environ.get("FOUNDRY_LIVE") != "1":
        sys.stderr.write("BLOCKED FOUNDRY_LIVE=1 and owner browser pins required\n")
        return 2
    if sys.argv[1:] not in ([], ["--lighthouse"]):
        sys.stderr.write("BLOCKED browser arguments refused\n")
        return 2
    runpy.run_path(str(ROOT / "ci/pin_check.py"))["validate"]()
    kind = "lighthouse" if sys.argv[1:] else "playwright"
    child = subprocess.Popen(  # noqa: S603 -- finite reviewed Node script, own process group
        ["node", str(ROOT / "ci/playwright_e2e.mjs"), kind],  # noqa: S607 -- pinned image
        cwd=ROOT,
        env={"LANG": "C.UTF-8", "PATH": os.environ.get("PATH", os.defpath)},
        start_new_session=True,
    )
    try:
        child.wait(timeout=160)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        sys.stderr.write("BLOCKED browser drill exceeded bounded teardown\n")
        return 2
    if child.returncode:
        sys.stderr.write("BLOCKED browser pins/runtime or acceptance failed\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(bounded_main())
