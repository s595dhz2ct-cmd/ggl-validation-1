"""Owner-pinned Playwright/Chromium only. Bound server and browser teardown."""

import functools
import hashlib
import json
import os
import runpy
import signal
import subprocess
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Neither request paths nor form data enter logs.


def run(kind="playwright"):
    if os.environ.get("FOUNDRY_LIVE") != "1":
        raise RuntimeError("BLOCKED FOUNDRY_LIVE=1 and owner-reviewed browser pins required")
    pins = json.loads((ROOT / "ci/pins.json").read_bytes())
    runpy.run_path(str(ROOT / "ci/pin_check.py"))["validate"](pins=pins)
    if pins["tools"]["ci-image"]["digest"] is None or pins["tools"]["chromium"]["sha256"] is None:
        raise RuntimeError("BLOCKED unresolved_tool_pin: CI image/Chromium artifact")
    tool = "playwright-core" if kind == "playwright" else "lighthouse"
    lock_hash = pins["tools"][tool]["dependency_lock_sha256"]
    if lock_hash is None:
        raise RuntimeError("BLOCKED unresolved_tool_pin: npm dependency closure")
    installed = ROOT / ".tools/npm" / tool
    lock = installed / "package-lock.json"
    package = installed / "node_modules" / tool / "package.json"
    for path in (lock, package):
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise RuntimeError("BLOCKED missing_local_tool")
    if hashlib.sha256(lock.read_bytes()).hexdigest() != lock_hash:
        raise RuntimeError("BLOCKED installed npm lock mismatch")
    if json.loads(package.read_bytes())["version"] != pins["tools"][tool]["version_to_verify"]:
        raise RuntimeError("BLOCKED installed npm version mismatch")
    executable = ROOT / ".tools" / "chromium"
    if any(p.is_symlink() for p in (executable, *executable.parents)) or not executable.is_file():
        raise RuntimeError("BLOCKED missing_local_tool")
    if hashlib.sha256(executable.read_bytes()).hexdigest() != pins["tools"]["chromium"]["sha256"]:
        raise RuntimeError("BLOCKED browser pin mismatch")
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"}
    version = subprocess.run(
        ["node", "--version"],  # noqa: S607 -- fixed executable in the pinned CI image
        env=env,
        check=True,
        capture_output=True,
        timeout=5,
    )
    if version.stdout.strip().decode() != "v" + pins["tools"]["node"]["version"]:
        raise RuntimeError("BLOCKED Node version mismatch")
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8765), functools.partial(QuietHandler, directory=str(ROOT / "public"))
    )
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if kind == "playwright":
            subprocess.run(  # noqa: S603 -- fixed reviewed driver, no shell or vendor login
                ["node", str(ROOT / "ci/playwright_e2e.mjs")],  # noqa: S607 -- pinned CI image
                cwd=ROOT,
                env=env,
                check=True,
                timeout=35,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            checker = runpy.run_path(str(ROOT / "ci/lighthouse_check.py"))["check"]
            for preset in ("mobile", "desktop"):
                report = ROOT / ("lighthouse-" + preset + ".json")
                arguments = [
                    "node",
                    str(installed / "node_modules/lighthouse/cli/index.js"),
                    "http://127.0.0.1:8765/",
                    "--output=json",
                    "--output-path=" + str(report),
                    "--chrome-flags=--headless",
                    "--quiet",
                ]
                if preset == "desktop":
                    arguments.append("--preset=desktop")
                subprocess.run(  # noqa: S603 -- fixed pinned CLI, loopback URL and local browser
                    arguments,
                    cwd=ROOT,
                    env={**env, "CHROME_PATH": str(executable)},
                    check=True,
                    timeout=15,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                checker(json.loads(report.read_bytes()))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise RuntimeError("fixture server teardown incomplete")


def bounded_main():
    if os.environ.get("FOUNDRY_LIVE") != "1":
        sys.stderr.write("BLOCKED FOUNDRY_LIVE=1 and owner browser pins required\n")
        return 2
    if sys.argv[1:] in (["--child", "playwright"], ["--child", "lighthouse"]):
        run(sys.argv[2])
        return 0
    if sys.argv[1:] not in ([], ["--lighthouse"]):
        sys.stderr.write("BLOCKED browser arguments refused\n")
        return 2
    kind = "lighthouse" if sys.argv[1:] else "playwright"
    child = subprocess.Popen(  # noqa: S603 -- fixed reviewed script, own interpreter
        [sys.executable, "-I", str(Path(__file__).resolve()), "--child", kind],
        cwd=ROOT,
        env={"FOUNDRY_LIVE": "1", "LANG": "C.UTF-8", "PATH": os.environ.get("PATH", os.defpath)},
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        child.wait(timeout=45)
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
