"""Dependency-free checks for the exact reviewed, rendered public artifact."""

import hashlib
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = {"index.html", "styles.css", "waitlist.js", "privacy.html", "rights.html", "mark.svg"}
ALLOW = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "LicenseRef-Foundry-Original",
}


def check(kind, *, capsule_hash=None, evidence_hash=None):
    if kind not in {"artifact-integrity", "license-check"}:
        raise ValueError("unknown check")
    release = ROOT / "release/evidence.json"
    inventory = json.loads((ROOT / "ci/licenses.lock.json").read_bytes())
    if release.exists():
        # Expected hashes come from independent frozen custody. Never trust a
        # submitted file to choose its own expected artifact or rights evidence.
        if any(p.is_symlink() for p in (release, *release.parents)):
            raise ValueError("release evidence links refused")
        value = release.read_bytes()
        if len(value) > 16384 or hashlib.sha256(value).hexdigest() != evidence_hash:
            raise ValueError("untrusted release evidence")
        record = json.loads(value)
        capsule = record["capsule"]
        if (
            record["schema_version"] != 1
            or hashlib.sha256(
                json.dumps(
                    capsule, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()
            != capsule_hash
            or hashlib.sha256(
                json.dumps(
                    record["files"], sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()
            != capsule["file_manifest_hash"]
            or hashlib.sha256(json.dumps(record["files"], sort_keys=True).encode()).hexdigest()
            != capsule["artifact_hash"]
        ):
            raise ValueError("release evidence capsule binding refused")
        expected = {f["path"]: f["sha256"] for f in record["files"]}
        inventory = record["licenses"]
    elif capsule_hash is not None or evidence_hash is not None:
        raise ValueError("release evidence missing")
    else:
        expected = json.loads((ROOT / "ci/artifact.lock.json").read_bytes())
    output = ROOT / "public"
    if (
        any(p.is_symlink() for p in (output, *output.parents))
        or {p.name for p in output.iterdir()} != PUBLIC
    ):
        raise ValueError("file closure refused")
    actual = {}
    for name in PUBLIC:
        path = output / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
            raise ValueError("file closure refused")
        actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError("reviewed artifact changed")
    if kind == "license-check":
        package = json.loads((ROOT / "package.json").read_bytes())
        lock = json.loads((ROOT / "package-lock.json").read_bytes())
        if (
            package.get("scripts") != {}
            or package.get("dependencies") != {}
            or set(package)
            != {
                "name",
                "version",
                "private",
                "description",
                "scripts",
                "dependencies",
            }
        ):
            raise ValueError("unreviewed package or install script")
        if lock != {
            "name": "foundry-landing-waitlist",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {"": {"name": "foundry-landing-waitlist", "version": "1.0.0"}},
        }:
            raise ValueError("unreviewed locked dependency closure")
        if (
            inventory["dependencies"] != []
            or len(inventory["assets"]) != len(PUBLIC)
            or {asset["path"] for asset in inventory["assets"]} != PUBLIC
        ):
            raise ValueError("unreviewed dependency or rights closure")
        for asset in inventory["assets"]:
            if asset["license"] not in ALLOW or actual.get(asset["path"]) != asset["sha256"]:
                raise ValueError("license or content refused")


if __name__ == "__main__":
    try:
        # For a release the caller supplies capsule and evidence digests from
        # trusted custody; legacy default-template checks need neither argument.
        if len(sys.argv) not in {2, 4}:
            raise ValueError("check arguments refused")
        check(
            sys.argv[1],
            **(
                {"capsule_hash": sys.argv[2], "evidence_hash": sys.argv[3]}
                if len(sys.argv) == 4
                else {}
            ),
        )
    except (ValueError, OSError, KeyError, IndexError):
        sys.stderr.write("FAIL template check\n")
        raise SystemExit(1) from None
    sys.stdout.write("PASS " + sys.argv[1] + "\n")
