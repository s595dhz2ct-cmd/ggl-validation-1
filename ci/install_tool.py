"""Install only verified local CI artifacts; missing image/dependency pins refuse."""

import hashlib
import json
import os
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
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
    digest = hashlib.new(algorithm)
    with regular(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest


def command(arguments, *, root, input=None):
    # No shell, network, environment credentials or project install hooks.
    return subprocess.run(  # noqa: S603 -- fixed argument arrays after pin validation
        arguments,
        cwd=root,
        input=input,
        check=True,
        timeout=90,
        capture_output=True,
        env={"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"},
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


def dependency_lock(tool, name, root):
    expected = (
        "ci/semgrep-dependencies.txt"
        if name == "semgrep"
        else "ci/tool-locks/" + name + "/package-lock.json"
    )
    if tool["dependency_lock"] is None or tool["dependency_lock_sha256"] is None:
        raise ValueError("unresolved_tool_pin: " + name + ".dependency_lock")
    if tool["dependency_lock"] != expected:
        raise ValueError("dependency lock path refused")
    path = root / expected
    sha256sum(path, tool["dependency_lock_sha256"], root)
    return path


def install(name, *, root=ROOT, pins=None):
    if name not in TOOLS:
        raise ValueError("unknown CI tool")
    pins = PIN_CHECK["validate"](pins=pins)
    image = pins["tools"]["ci-image"]["digest"]
    if image is None:
        raise ValueError("unresolved_tool_pin: ci-image.digest")
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise ValueError("CI image digest refused")
    PIN_CHECK["hex_pin"](image[7:], 64)
    tool = pins["tools"][name]
    # Scoped npm name is registry metadata, never part of a filesystem path.
    filename = tool["artifact"].removeprefix("@playwright/")
    if re.fullmatch(r"[A-Za-z0-9_.+-]+", filename) is None:
        raise ValueError("artifact path refused")
    artifact = root / ".tools/downloads" / filename
    if tool["artifact_format"] == "npm-tarball":
        if digest_file(artifact, "sha512").digest() != PIN_CHECK["integrity_bytes"](
            tool["integrity"]
        ):
            raise ValueError("npm integrity mismatch")
        lock_path = dependency_lock(tool, name, root)
        lock = json.loads(lock_path.read_bytes())
        packages = lock["packages"]
        dependencies = {tool["npm_package"]: tool["version_to_verify"]}
        if (
            lock["lockfileVersion"] != 3
            or packages[""]["dependencies"] != dependencies
            or lock["name"] != "foundry-ci-" + name
            or lock["version"] != "1.0.0"
            or packages["node_modules/" + tool["npm_package"]]["version"]
            != tool["version_to_verify"]
            or packages["node_modules/" + tool["npm_package"]]["integrity"] != tool["integrity"]
        ):
            raise ValueError("npm exact version/integrity lock refused")
        for path, package in packages.items():
            if not path:
                continue
            PIN_CHECK["integrity_bytes"](package["integrity"])
            if (
                re.fullmatch(r"node_modules/(?:[@A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+", path) is None
                or ".." in path
                or package.get("link")
                or not re.fullmatch(
                    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", package["version"]
                )
                or not package["resolved"].startswith("https://registry.npmjs.org/")
            ):
                raise ValueError("npm dependency closure refused")
        node = command(["node", "--version"], root=root)
        if node.stdout.strip().decode() != "v" + pins["tools"]["node"]["version"]:
            raise ValueError("Node version mismatch")
        target = root / ".tools/npm" / name
        if any(p.is_symlink() for p in (target, *target.parents)) or target.exists():
            raise ValueError("preserve existing npm tool directory")
        cache_path = root / ".tools/npm-cache"
        if any(p.is_symlink() for p in (cache_path, *cache_path.parents)) or (
            cache_path.exists() and not cache_path.is_dir()
        ):
            raise ValueError("npm cache links or type refused")
        target.mkdir(parents=True)
        (target / "package-lock.json").write_bytes(lock_path.read_bytes())
        (target / "package.json").write_text(
            json.dumps(
                {
                    "name": lock["name"],
                    "version": "1.0.0",
                    "private": True,
                    "dependencies": dependencies,
                }
            )
        )
        cache = str(cache_path)
        command(
            [
                "npm",
                "cache",
                "add",
                "--offline",
                "--ignore-scripts",
                "--cache",
                cache,
                str(artifact),
            ],
            root=root,
        )
        command(
            [
                "npm",
                "ci",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--cache",
                cache,
                "--prefix",
                str(target),
            ],
            root=root,
        )
        installed = json.loads(
            (target / "node_modules" / tool["npm_package"] / "package.json").read_bytes()
        )
        if installed["version"] != tool["version_to_verify"]:
            raise ValueError("installed npm version mismatch")
        return
    sha256sum(artifact, tool["sha256"], root)
    target = root / ".tools" / name
    if any(p.is_symlink() for p in (target, *target.parents)) or target.exists():
        raise ValueError("preserve existing tool directory")
    if name == "semgrep":
        lock = dependency_lock(tool, name, root)
        lines = lock.read_text().replace("\\\n", " ").splitlines()
        for line in lines:
            if (
                line.strip()
                and not line.startswith("#")
                and re.fullmatch(
                    r"[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9_.+-]*(?:\s+--hash=sha256:[0-9a-f]{64})+\s*",
                    line,
                )
                is None
            ):
                raise ValueError("unhashed or remote pip requirement refused")
        command([sys.executable, "-I", "-m", "venv", str(target)], root=root)
        command(
            [
                str(target / "bin/python"),
                "-I",
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "--no-index",
                "--find-links",
                str(root / ".tools/downloads"),
                "--only-binary=:all:",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "-r",
                str(root / "ci/semgrep-constraints.txt"),
                "-r",
                str(lock),
            ],
            root=root,
        )
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
        if tool["database_snapshot"] is None or tool["database_sha256"] is None:
            raise ValueError("unresolved_tool_pin: osv-scanner.database_snapshot/database_sha256")
        snapshot = tool["database_snapshot"]
        if not isinstance(snapshot, str) or re.fullmatch(r"[A-Za-z0-9_.+-]+", snapshot) is None:
            raise ValueError("OSV database artifact path refused")
        sha256sum(root / ".tools/downloads" / snapshot, tool["database_sha256"], root)
        with artifact.open("rb") as source, output.open("xb") as destination:
            shutil.copyfileobj(source, destination)
    output.chmod(0o700)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("CI installer arguments refused")
        install(sys.argv[1])
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, tarfile.TarError):
        sys.stderr.write("BLOCKED CI tool pin, artifact integrity or dependency closure\n")
        raise SystemExit(2) from None
    sys.stdout.write("PASS pinned CI tool installation\n")
