"""Offline pin/schema and workflow checks; no installation or release authority."""

import base64
import binascii
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


def validate(pins=None, release=None, workflows=None, constraints=None):
    pins = json.loads((ROOT / "ci/pins.json").read_bytes()) if pins is None else pins
    release = (
        json.loads((ROOT / "ci/release-pins.json").read_bytes()) if release is None else release
    )
    if (
        pins["schema_version"] != 1
        or release["schema_version"] != 1
        or pins["release_eligible"] is not False
        or pins["evidence_date"] != "2026-10-11"
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
    image = pins["tools"]["ci-image"]["digest"]
    if image is not None:
        if not isinstance(image, str) or not image.startswith("sha256:"):
            raise ValueError("invalid CI image digest")
        hex_pin(image[7:], 64)
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
