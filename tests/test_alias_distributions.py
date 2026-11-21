"""The PyPI alias installs the SDK without owning any of its files or commands."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    # Pytest supplies tomli on 3.10; mypy targets 3.10 even when run on newer Python.
    import tomli as tomllib  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]
ALIAS = "trustedrouter"


def test_alias_versions() -> None:
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    project = tomllib.loads(
        (ROOT / "aliases" / ALIAS / "pyproject.toml").read_text()
    )["project"]
    assert project["urls"] == root["urls"]
    dependencies = [*project["dependencies"], *(
        dependency for extra in project["optional-dependencies"].values()
        for dependency in extra
    )]
    for dependency in dependencies:
        requirement = Requirement(dependency)
        assert requirement.name == "trusted-router-py"
        (floor,) = requirement.specifier
        assert floor.operator == ">="
        assert Version(floor.version) <= Version(root["version"])
    assert project["version"] == "0.10.0"


def build_alias(name: str, destination: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv is required to build alias distributions"
    command = [uv, "build", str(ROOT / "aliases" / name),
               "--python", sys.executable, "--out-dir", str(destination)]
    # Prefer the cached backend; only retry online when build requirements are missing.
    for offline in (True, False):
        result = subprocess.run(  # noqa: S603 -- Test-owned argv, no shell.
            [*command, *(["--offline"] if offline else [])],
            cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
        )
        output = result.stdout + result.stderr
        if result.returncode == 0:
            return
        backend_unavailable = (
            "Failed to resolve requirements from `build-system.requires`" in output
            or "Failed to install requirements from `build-system.requires`" in output
        )
        assert backend_unavailable, output
        if not offline:
            pytest.skip(f"Cannot obtain the hatchling build backend: {output}")


def test_alias_distribution(tmp_path: Path) -> None:
    # The release workflow checks the exact artifacts that will be uploaded.
    artifact_dir = os.environ.get("ALIAS_DIST_DIR")
    destination = ROOT / artifact_dir if artifact_dir else tmp_path / "dist"
    if not artifact_dir:
        build_alias(ALIAS, destination)
    (wheel_path,) = destination.glob("*.whl")
    (sdist_path,) = destination.glob("*.tar.gz")
    dist = f"{ALIAS}-0.10.0"
    with zipfile.ZipFile(wheel_path) as wheel:
        names = wheel.namelist()
        assert names
        assert all(path.startswith(f"{dist}.dist-info/") for path in names)
        assert not any(Path(path).name == "entry_points.txt" for path in names)
        metadata = BytesParser().parsebytes(wheel.read(f"{dist}.dist-info/METADATA"))
    assert metadata["Name"] == ALIAS
    assert metadata["Version"] == "0.10.0"
    assert metadata["Requires-Python"] == ">=3.10"
    assert metadata["License-Expression"] == "Apache-2.0"
    assert set(metadata.get_all("Provides-Extra", [])) == {"attestation", "receipts"}
    assert {Requirement(value) for value in metadata.get_all("Requires-Dist", [])} == {
        Requirement("trusted-router-py>=0.10.0"),
        Requirement('trusted-router-py[attestation]>=0.10.0; extra == "attestation"'),
        Requirement('trusted-router-py[receipts]>=0.10.0; extra == "receipts"'),
    }
    with tarfile.open(sdist_path) as sdist:
        files = {entry.name for entry in sdist if entry.isfile()}
        expected = {
            f"{dist}/{filename}" for filename in
            ("pyproject.toml", "README.md", "LICENSE", "PKG-INFO")
        }
        # Hatchling may include the enclosing repository's ignore file.
        assert expected <= files <= expected | {f"{dist}/.gitignore"}
        pkg_info = sdist.extractfile(f"{dist}/PKG-INFO")
        assert pkg_info is not None
        assert BytesParser().parsebytes(pkg_info.read()).as_bytes() == metadata.as_bytes()
