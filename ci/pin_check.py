"""Offline pin/schema and workflow checks; no installation or release authority."""

import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSIONS = {
    "gitleaks": "8.30.1",
    "osv-scanner": "2.6.0",
    "semgrep": "1.178.0",
    "playwright": "1.63.0",
    "playwright-core": "1.63.0",
    "lighthouse": "13.5.0",
}
ACTION_TAGS = {
    "actions/checkout": "v7.0.1",
    "actions/upload-artifact": "v7.0.1",
    "actions/download-artifact": "v8.0.1",
    "tailscale/github-action": "v4.2.0",
}
ALLOW = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0"]
BASES = {
    "node": "node@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c",
    "python": "python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3",
}
LOCKS = {
    "checks": ("ci/check-tools/package-lock.json", 116),
    "deploy": ("ci/deploy-tool/package-lock.json", 91),
}
COMMANDS = {
    "tests": "python -I -m unittest discover -s ci -p test_static.py",
    "playwright": "node ci/playwright_e2e.mjs playwright",
    "lighthouse": "node ci/playwright_e2e.mjs lighthouse",
    "gitleaks": ".tools/gitleaks/bin/gitleaks dir public --redact --no-banner",
    "semgrep": (
        ".tools/semgrep/bin/semgrep scan --config ci/semgrep.yml --metrics=off "
        "--disable-version-check --error --strict public"
    ),
    "osv-scanner": "python -I ci/install_tool.py --scan-osv",
    "license-check": "python -I ci/check.py license-check",
    "artifact-integrity": "python -I ci/check.py artifact-integrity",
}


def ci_workflow():
    """Finite workflow contract: conditional, omitted or masked tools cannot pass."""
    text = """# Generated from ci/pin_check.py:ci_workflow; review both together.
name: landing-template-ci
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: landing-ci-${{ github.ref }}
  cancel-in-progress: true
defaults:
  run:
    shell: bash
env:
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1'
  SEMGREP_SEND_METRICS: 'off'
  SEMGREP_ENABLE_VERSION_CHECK: '0'
  npm_config_update_notifier: 'false'
# Network acquisition is confined to the download step, plus the owner-approved
# live OSV query. All installs use verified local artifacts and complete locks.
jobs:
"""
    for name, command in COMMANDS.items():
        browser = name in {"playwright", "lighthouse"}
        text += f"""  {name}:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    container:
      image: {BASES["node" if browser else "python"]}
      options: --user 1000:1000 --cap-drop=ALL --security-opt=no-new-privileges
    steps:
      - name: Exact secret-free checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Validate pins and workflow coverage
        run: {"node ci/npm_tool.mjs validate" if browser else "python -I ci/pin_check.py"}
"""
        if browser or name in {"gitleaks", "semgrep", "osv-scanner"}:
            download = (
                "node ci/npm_tool.mjs download"
                if browser
                else "python -I ci/install_tool.py --download " + name
            )
            install = (
                "node ci/npm_tool.mjs install"
                if browser
                else "python -I ci/install_tool.py " + name
            )
            text += f"""      - name: Download hash-checked tool closure
        run: {download}
      - name: Install verified local artifacts offline
        run: {install}
"""
        text += f"""      - name: Run {name}
        run: |
          set -euo pipefail
          {command}
"""
    return text


def lock_bytes(root, relative, expected):
    hex_pin(expected, 64)
    path = root / relative
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("dependency lock links refused")
    if path.stat().st_nlink != 1 or not path.is_file():
        raise ValueError("dependency lock type refused")
    value = path.read_bytes()
    if hashlib.sha256(value).hexdigest() != expected:
        raise ValueError("dependency lock SHA-256 mismatch")
    return value


def npm_lock(root, record, group, tools):
    relative, count = LOCKS[group]
    if record["dependency_lock"] != relative:
        raise ValueError("dependency lock path refused")
    lock = json.loads(lock_bytes(root, relative, record["dependency_lock_sha256"]))
    package = json.loads((root / relative).with_name("package.json").read_bytes())
    dependencies = {t["npm_package"]: t["version_to_verify"] for t in tools}
    if (
        lock["lockfileVersion"] != 3
        or lock["name"]
        != "foundry-landing-" + ("check-tools" if group == "checks" else "deploy-tool")
        or lock["version"] != "1.0.0"
        or lock["packages"][""]["dependencies"] != dependencies
        or package
        != {"name": lock["name"], "version": "1.0.0", "private": True, "dependencies": dependencies}
        or len(lock["packages"]) != count + 1
    ):
        raise ValueError("npm dependency closure refused")
    for path, item in lock["packages"].items():
        if not path:
            continue
        integrity_bytes(item.get("integrity"))
        if (
            not re.fullmatch(r"node_modules/(?:[@A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+", path)
            or ".." in path
            or item.get("link")
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", item["version"])
            or not item["resolved"].startswith("https://registry.npmjs.org/")
        ):
            raise ValueError("npm dependency closure refused")
    for tool in tools:
        item = lock["packages"]["node_modules/" + tool["npm_package"]]
        if item["version"] != tool["version_to_verify"] or item["integrity"] != tool["integrity"]:
            raise ValueError("npm exact version/integrity lock refused")
    return lock


def pip_lock(root, tool):
    if tool["dependency_lock"] != "ci/semgrep-requirements.txt":
        raise ValueError("dependency lock path refused")
    value = lock_bytes(root, tool["dependency_lock"], tool["dependency_lock_sha256"])
    lines = value.decode().replace("\\\n", " ").splitlines()
    requirements = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if (
            re.fullmatch(
                r"[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9_.+-]*(?:\s+--hash=sha256:[0-9a-f]{64})+\s*",
                line,
            )
            is None
        ):
            raise ValueError("unhashed or remote pip requirement refused")
        requirements.append(line)
    if len(requirements) != 66 or not any(
        line.startswith("semgrep==" + tool["version_to_verify"] + " ")
        and "--hash=sha256:" + tool["sha256"] in line
        for line in requirements
    ):
        raise ValueError("Semgrep complete dependency closure refused")
    return value


def hex_pin(value, size):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is None:
        raise ValueError("invalid immutable hash")


def integrity_bytes(value):
    if not isinstance(value, str) or not value.startswith("sha512-"):
        raise ValueError("invalid npm integrity")
    try:
        digest = base64.b64decode(value[7:], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid npm integrity") from None
    if len(digest) != 64 or "sha512-" + base64.b64encode(digest).decode() != value:
        raise ValueError("invalid npm integrity")
    return digest


def validate(pins=None, release=None, workflows=None, constraints=None, root=ROOT):
    pins = json.loads((ROOT / "ci/pins.json").read_bytes()) if pins is None else pins
    release = (
        json.loads((ROOT / "ci/release-pins.json").read_bytes()) if release is None else release
    )
    if (
        pins["schema_version"] != 1
        or release["schema_version"] != 1
        or pins["release_eligible"] is not False
        or pins["evidence_date"] != "2026-10-15"
        or pins["release_cutoff"] != "2026-09-27"
        or pins["license_allowlist"] != ALLOW
    ):
        raise ValueError("pin scope or release barrier changed")
    for name, version in VERSIONS.items():
        tool = pins["tools"][name]
        if (
            tool["version_to_verify"] != version
            or tool["usage_scope"] != "ci-only"
            or not tool["source_urls"]
            or tool["source"] not in tool["source_urls"]
            or not all(url.startswith("https://") for url in tool["source_urls"])
            or date.fromisoformat(tool["release_date"]) > date(2026, 9, 27)
            or tool["artifact"] not in tool["artifacts"]
        ):
            raise ValueError("tool version, provenance or artifact refused")
        for artifact, digest in tool["artifacts"].items():
            if re.fullmatch(r"[@A-Za-z0-9_.+/-]+", artifact) is None or ".." in artifact:
                raise ValueError("invalid artifact name")
            if tool["artifact_format"] == "npm-tarball":
                integrity_bytes(digest)
            else:
                hex_pin(digest, 64)
        if tool["artifact_format"] == "npm-tarball":
            if (
                tool["npm_package"]
                != {
                    "playwright": "@playwright/test",
                    "playwright-core": "playwright-core",
                    "lighthouse": "lighthouse",
                }[name]
                or tool["integrity"] != tool["artifacts"][tool["artifact"]]
                or not tool["tarball"].startswith("https://registry.npmjs.org/")
                or not tool["tarball"].endswith("-" + version + ".tgz")
                or tool["sha256"] is not None
            ):
                raise ValueError("npm version/integrity binding refused")
        elif tool["sha256"] != tool["artifacts"][tool["artifact"]]:
            raise ValueError("artifact hash binding refused")
        if "dependency_lock" in tool:
            if (tool["dependency_lock"] is None) != (tool["dependency_lock_sha256"] is None):
                raise ValueError("incomplete dependency lock pin")
            if tool["dependency_lock_sha256"] is not None:
                hex_pin(tool["dependency_lock_sha256"], 64)
        if name == "semgrep":
            if tool["license"] != "LGPL-2.1-or-later" or (
                tool.get("owner_license_decision") != "keep_ci_only"
            ):
                raise ValueError("CI-only owner license decision required")
        elif tool["license"] not in ALLOW:
            raise ValueError("tool license metadata refused")
    node = pins["tools"]["node"]
    if node["version"] != "22.23.3" or node["satisfies_requirements"] != {
        "playwright": ">=20",
        "lighthouse": ">=22.19",
    }:
        raise ValueError("Node tool requirements refused")
    if (
        pins["tools"]["playwright"]["node_requirement"] != ">=20"
        or pins["tools"]["playwright-core"]["node_requirement"] != ">=20"
        or pins["tools"]["lighthouse"]["node_requirement"] != ">=22.19"
        or pins["tools"]["chromium"]["revision"] != "1243"
        or pins["tools"]["chromium"]["version_to_verify"] != "153.0.8010.12"
    ):
        raise ValueError("browser/Node pairing refused")
    for tool_name, field in (
        ("chromium", "sha256"),
        ("osv-scanner", "database_sha256"),
        ("codex-cli", "sha256"),
        ("openhands", "sha256"),
        ("encrypted-browser-transport", "sha256"),
    ):
        value = pins["tools"][tool_name][field]
        if value is not None:
            hex_pin(value, 64)
    if pins["tools"]["ci-image"]["digests"] != BASES or release["ci_base_image_digests"] != BASES:
        raise ValueError("unresolved_tool_pin: ci-image.digests refused")
    for name, image in BASES.items():
        if image != name + "@" + pins["tools"][name]["digest"]:
            raise ValueError("base image binding refused")
    browser = pins["tools"]["chromium"]
    if (
        browser["sha256"] != "a9da028861a0cf789ff25c2fed45f5f1aaf969ed9247835b6a7821a4f7af9d1d"
        or browser["url"]
        != "https://storage.googleapis.com/chrome-for-testing-public/"
        "153.0.8010.12/linux64/chrome-headless-shell-linux64.zip"
        or browser["license"] != "BSD-3-Clause (Chromium)"
    ):
        raise ValueError("Chromium artifact evidence refused")
    osv = pins["tools"]["osv-scanner"]
    if osv["database"] != "live" or osv.get("owner_decision") != pins.get("owner_decision"):
        raise ValueError("OSV live database owner decision required")
    check_tools = [pins["tools"][n] for n in ("playwright", "playwright-core", "lighthouse")]
    for tool in check_tools:
        npm_lock(root, tool, "checks", check_tools)
    pip_lock(root, pins["tools"]["semgrep"])
    deploy = release["deploy_tool_lock"]
    if (
        deploy["name"] != "wrangler"
        or deploy["version"] != "4.142.0"
        or deploy["license"] != "MIT OR Apache-2.0"
    ):
        raise ValueError("deploy tool evidence refused")
    npm_lock(
        root,
        deploy,
        "deploy",
        [
            {
                "npm_package": deploy["name"],
                "version_to_verify": deploy["version"],
                "integrity": deploy["integrity"],
            }
        ],
    )
    for name, tag in ACTION_TAGS.items():
        action = release["actions"][name]
        hex_pin(action["commit"], 40)
        if (
            action["tag"] != tag
            or date.fromisoformat(action["release_date"]) > date(2026, 9, 27)
            or not action["source_urls"]
        ):
            raise ValueError("Action provenance refused")
    actions = release["actions"]
    if (
        release["checkout_action_sha"] != actions["actions/checkout"]["commit"]
        or pins["tools"]["actions-checkout"]["commit"] != release["checkout_action_sha"]
        or release["artifact_actions_sha"]
        != {
            "upload": actions["actions/upload-artifact"]["commit"],
            "download": actions["actions/download-artifact"]["commit"],
        }
        or release["tailscale_action_sha"] != actions["tailscale/github-action"]["commit"]
    ):
        raise ValueError("Action hash binding refused")
    workflows = (
        [(ROOT / ".github/workflows" / name).read_text() for name in ("ci.yml", "release.yml")]
        if workflows is None
        else workflows
    )
    seen = set()
    for workflow in workflows:
        for line in workflow.splitlines():
            if "uses:" not in line:
                continue
            match = re.fullmatch(
                r"\s*(?:-\s*)?uses:\s*([a-z/-]+)@([0-9a-f]{40})\s+# (v[0-9.]+)\s*", line
            )
            if not match:
                raise ValueError("floating or uncommented Action refused")
            name, commit, tag = match.groups()
            if (
                name not in actions
                or commit != actions[name]["commit"]
                or tag != actions[name]["tag"]
            ):
                raise ValueError("unreviewed Action refused")
            seen.add(name)
    if seen != set(ACTION_TAGS):
        raise ValueError("Action coverage incomplete")
    if workflows[0] != ci_workflow():
        raise ValueError("CI job tool execution/coverage refused")
    constraints = (
        (ROOT / "ci/semgrep-constraints.txt").read_text() if constraints is None else constraints
    )
    requirements = " ".join(
        line.strip().removesuffix("\\").strip()
        for line in constraints.splitlines()
        if line.strip() and not line.startswith("#")
    )
    expected = "semgrep==1.178.0 " + " ".join(
        "--hash=sha256:" + digest for digest in pins["tools"]["semgrep"]["artifacts"].values()
    )
    if requirements != expected:
        raise ValueError("Semgrep hashed constraints refused")
    return pins


if __name__ == "__main__":
    try:
        validate()
    except (ValueError, KeyError, TypeError, OSError):
        sys.stderr.write("FAIL CI pin metadata\n")
        raise SystemExit(1) from None
    sys.stdout.write("PASS CI pin metadata; release remains blocked\n")
