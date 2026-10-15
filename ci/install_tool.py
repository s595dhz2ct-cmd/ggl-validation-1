"""Stage hash-checked Python/binary tools, then install from local artifacts only."""

import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_CHECK = runpy.run_path(str(ROOT / "ci/pin_check.py"))
TOOLS = {"gitleaks", "osv-scanner", "semgrep", "playwright", "playwright-core", "lighthouse"}


def regular(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("local artifact links refused")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("local artifact type refused")
    return path


def digest_file(path, algorithm):
    with regular(path).open("rb") as handle:
        return hashlib.file_digest(handle, algorithm)


def command(arguments, *, root, input=None):
    # The acquisition phase is explicit. Neither phase inherits CI credentials.
    return subprocess.run(  # noqa: S603 -- finite checked argument arrays, no shell
        arguments,
        cwd=root,
        input=input,
        check=True,
        timeout=300,
        capture_output=True,
        env={
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": "C.UTF-8",
            "HOME": str(root / ".tools/home"),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        },
    )


def sha256sum(path, expected, root):
    PIN_CHECK["hex_pin"](expected, 64)
    if digest_file(path, "sha256").hexdigest() != expected:
        raise ValueError("artifact SHA-256 mismatch")
    command(
        ["sha256sum", "--check", "--strict", "-"],
        root=root,
        input=(expected + "  " + str(path.relative_to(root)) + "\n").encode(),
    )


def checked(name, pins):
    if name not in TOOLS:
        raise ValueError("unknown CI tool")
    return PIN_CHECK["validate"](pins=pins)


def download(name, *, root=ROOT, pins=None):
    pins = checked(name, pins)
    if name not in {"gitleaks", "osv-scanner", "semgrep"}:
        raise ValueError("npm acquisition requires the pinned Node runner")
    directory = root / ".tools/downloads"
    if directory.exists() or any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ValueError("preserve existing tool downloads")
    directory.mkdir(parents=True)
    tool = pins["tools"][name]
    if name == "semgrep":
        lock = PIN_CHECK["pip_lock"](root, tool)
        if not lock:
            raise ValueError("missing dependency lock")
        command(
            [
                sys.executable,
                "-I",
                "-m",
                "pip",
                "download",
                "--require-hashes",
                "--no-deps",
                "--only-binary=:all:",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "--index-url",
                "https://pypi.org/simple",
                "--dest",
                str(directory),
                "-r",
                str(root / tool["dependency_lock"]),
            ],
            root=root,
        )
    else:
        # Release URLs are fixed by the reviewed version/artifact metadata.
        expected = (
            "https://github.com/"
            + ("gitleaks/gitleaks" if name == "gitleaks" else "google/osv-scanner")
            + "/releases/download/v"
            + tool["version_to_verify"]
            + "/"
            + tool["artifact"]
        )
        if tool["url"] != expected:
            raise ValueError("download URL refused")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with (
            opener.open(expected, timeout=60) as response,
            (directory / tool["artifact"]).open("xb") as out,
        ):
            shutil.copyfileobj(response, out)
    sha256sum(directory / tool["artifact"], tool["sha256"], root)


def install(name, *, root=ROOT, pins=None):
    pins = checked(name, pins)
    if name in {"playwright", "playwright-core", "lighthouse"}:
        PIN_CHECK["npm_lock"](
            root,
            pins["tools"][name],
            "checks",
            [pins["tools"][n] for n in ("playwright", "playwright-core", "lighthouse")],
        )
        command(["node", "ci/npm_tool.mjs", "install"], root=root)
        return
    tool = pins["tools"][name]
    artifact = root / ".tools/downloads" / tool["artifact"]
    sha256sum(artifact, tool["sha256"], root)
    target = root / ".tools" / name
    if any(p.is_symlink() for p in (target, *target.parents)) or target.exists():
        raise ValueError("preserve existing tool directory")
    if name == "semgrep":
        PIN_CHECK["pip_lock"](root, tool)
        command([sys.executable, "-I", "-m", "venv", str(target)], root=root)
        command(
            [
                str(target / "bin/python"),
                "-I",
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "--no-deps",
                "--no-index",
                "--find-links",
                str(root / ".tools/downloads"),
                "--only-binary=:all:",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "-r",
                str(root / tool["dependency_lock"]),
            ],
            root=root,
        )
        command([str(target / "bin/python"), "-I", "-m", "pip", "check"], root=root)
        return
    output = target / "bin" / name
    output.parent.mkdir(parents=True)
    if name == "gitleaks":
        with tarfile.open(artifact, "r:gz") as archive:
            member = archive.getmember("gitleaks")
            if not member.isfile():
                raise ValueError("gitleaks archive member refused")
            with archive.extractfile(member) as source, output.open("xb") as destination:
                shutil.copyfileobj(source, destination)
    else:
        if tool["database"] != "live" or not tool["owner_decision"]:
            raise ValueError("OSV live database owner decision required")
        with artifact.open("rb") as source, output.open("xb") as destination:
            shutil.copyfileobj(source, destination)
    output.chmod(0o700)


def scan_osv(*, root=ROOT):
    pins = PIN_CHECK["validate"]()
    executable = str(root / ".tools/osv-scanner/bin/osv-scanner")
    version = command([executable, "--version"], root=root).stdout.decode().strip()
    if pins["tools"]["osv-scanner"]["version_to_verify"] not in version:
        raise ValueError("OSV version mismatch")
    sys.stdout.write(
        version + "\nOSV database=live scan_started=" + datetime.now(UTC).isoformat() + "\n"
    )
    sys.stdout.flush()
    # Include CI dependency closures: the shipped application itself has none.
    directory = root / ".tools/osv-input"
    directory.mkdir()
    shutil.copyfile(root / "ci/semgrep-requirements.txt", directory / "requirements.txt")
    arguments = [executable, "scan", "source", "--format", "json", "--output", "osv-report.json"]
    for path in (
        "package-lock.json",
        "ci/check-tools/package-lock.json",
        "ci/deploy-tool/package-lock.json",
        ".tools/osv-input/requirements.txt",
    ):
        arguments.extend(["--lockfile", path])
    try:
        command(arguments, root=root)
    finally:
        sys.stdout.write("OSV live scan_finished=" + datetime.now(UTC).isoformat() + "\n")
        report = root / "osv-report.json"
        if report.is_file():
            value = json.loads(report.read_bytes())
            modified = []

            def collect(item):
                if isinstance(item, dict):
                    if isinstance(item.get("modified"), str):
                        modified.append(item["modified"])
                    for child in item.values():
                        collect(child)
                elif isinstance(item, list):
                    for child in item:
                        collect(child)

            collect(value)
            sys.stdout.write(
                "OSV returned_record_modified="
                + (
                    max(modified)
                    if modified
                    else "none; live API supplies no global snapshot timestamp"
                )
                + "\n"
            )


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--download":
            download(sys.argv[2])
        elif sys.argv[1:] == ["--scan-osv"]:
            scan_osv()
        elif len(sys.argv) == 2:
            install(sys.argv[1])
        else:
            raise ValueError("CI installer arguments refused")
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        sys.stderr.write(
            "BLOCKED CI tool pin, artifact integrity, dependency closure or tool execution: "
            + type(error).__name__
            + "\n"
        )
        raise SystemExit(2) from None
    sys.stdout.write("PASS pinned CI tool operation\n")
