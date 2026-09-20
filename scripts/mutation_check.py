"""Fail-closed mutation proofs on a temporary copy; stdlib only.

Each manifest entry must match exactly. Baselines must pass, mutants must fail
with pytest exit 1 (not import/collection errors), and original bytes are restored
from memory in finally even on subprocess failure or interruption.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def mutated(root: Path, mutation: dict[str, Any]) -> Iterator[None]:
    path = root / mutation["file"]
    original = path.read_bytes()
    before = mutation["before"].encode()
    after = mutation["after"].encode()
    count = original.count(before)
    expected = mutation.get("expected_count", 1)
    occurrence = mutation.get("occurrence", 0)
    if not before or count != expected or not 0 <= occurrence < count:
        raise ValueError(f"STALE {mutation['name']}: expected {expected} matches, got {count}")
    pieces = original.split(before)
    changed = before.join(pieces[:occurrence + 1]) + after + before.join(pieces[occurrence + 1:])
    if changed == original:
        raise ValueError(f"Invalid no-op mutation: {mutation['name']}")
    try:
        path.write_bytes(changed)
        yield
    finally:
        path.write_bytes(original)
        if path.read_bytes() != original:
            raise OSError(f"Failed to restore {path}")


def run(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Fixed argv from our manifest; never a shell command or external input.
    return subprocess.run(  # noqa: S603 -- Fixed Python module argv, shell disabled.
        [sys.executable, *args], cwd=root, env=env, capture_output=True, text=True,
        timeout=120, check=False,
    )


def pytest_args(test: str) -> list[str]:
    # Disable full-suite coverage threshold for focused proofs, not for CI pytest.
    return ["-m", "pytest", "-q", "-o", "addopts=", "--no-cov", test]


def require_killed(result: subprocess.CompletedProcess[str], name: str) -> None:
    if result.returncode == 0:
        raise ValueError(f"SURVIVED {name}")
    if result.returncode != 1 or "FAILED " not in result.stdout:
        raise ValueError(f"Invalid proof {name}: pytest did not report a test failure\n"
                         f"{result.stdout}\n{result.stderr}")


def static_proofs(root: Path) -> list[dict[str, object]]:
    probes = [
        ("unproven-object", "mypy", "attr-defined", '''
import httpx

def unsafe(response: httpx.Response) -> object:
    payload: object = response.json()
    return payload.get("key")
'''),
        ("untyped-decode", "boundary", "BND001", '''
import json
payload = json.loads("[]")
'''),
        ("cast-laundering", "boundary", "BND002", '''
from typing import cast
payload: object = []
record = cast(dict[str, object], payload)
'''),
        ("scalar-laundering", "boundary", "BND002", '''
payload: dict[str, object] = {"key": 7}
key = str(payload.get("key") or "")
'''),
        ("plain-header-read", "boundary", "BND003", '''
headers: dict[str, str] = {"authorization": "x"}
key = headers["Authorization"]
'''),
        ("plain-header-copy", "boundary", "BND003", '''
headers: dict[str, str] = {}
merged = dict(headers)
'''),
        ("blind-except", "ruff", "BLE001", '''
try:
    raise ValueError("bad shape")
except Exception:
    pass
'''),
        ("blanket-type-ignore", "ruff", "PGH003", 'x = 1  # type: ignore\n'),
        ("blanket-noqa", "ruff", "PGH004", 'x = 1  # noqa\n'),
    ]
    results: list[dict[str, object]] = []
    path = root / "src/trustedrouter/_boundary_probe.py"
    for name, gate, diagnostic, source in probes:
        path.write_text(source)
        try:
            if gate == "mypy":
                args = ["-m", "mypy", "--strict", str(path)]
            elif gate == "ruff":
                args = ["-m", "ruff", "check", str(path)]
            else:
                args = ["scripts/boundary_check.py", str(path)]
            result = run(root, args)
            if result.returncode != 1 or diagnostic not in result.stdout:
                raise ValueError(f"Static probe {name} escaped {diagnostic}: {result.stdout}")
            print(f"STATIC REJECTED {name} ({diagnostic})", flush=True)
            results.append({"name": name, "diagnostic": diagnostic, "result": "rejected"})
        finally:
            path.unlink()
    return results


def check(report_path: Path | None = None) -> None:
    started = time.monotonic()
    manifest = json.loads((ROOT / "scripts/mutations.json").read_bytes())
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="trustedrouter-mutations-") as temporary:
        root = Path(temporary)
        for directory in ("src", "tests", "scripts"):
            shutil.copytree(ROOT / directory, root / directory,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
        gate = run(root, ["scripts/boundary_check.py"])
        if gate.returncode:
            raise ValueError(f"Boundary baseline failed: {gate.stdout}\n{gate.stderr}")
        # Check all stale patterns up front, including entries whose tests share a baseline.
        for mutation in manifest:
            with mutated(root, mutation):
                pass
        for test in dict.fromkeys(mutation["test"] for mutation in manifest):
            result = run(root, pytest_args(test))
            if result.returncode:
                raise ValueError(f"Baseline failed: {test}\n{result.stdout}\n{result.stderr}")
        print("All focused baselines passed", flush=True)
        for mutation in manifest:
            tick = time.monotonic()
            with mutated(root, mutation):
                result = run(root, pytest_args(mutation["test"]))
                require_killed(result, mutation["name"])
            elapsed = time.monotonic() - tick
            print(f"KILLED {mutation['name']} ({elapsed:.2f}s)", flush=True)
            results.append({"name": mutation["name"], "file": mutation["file"],
                            "test": mutation["test"], "result": "killed",
                            "seconds": round(elapsed, 3)})
        static = static_proofs(root)
    elapsed = time.monotonic() - started
    report = {"mutations": results, "static_proofs": static, "seconds": round(elapsed, 3)}
    if report_path is not None:
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(results)} mutations killed; {len(static)} static probes rejected; "
          f"wall time {elapsed:.2f}s", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        check(args.report)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Mutation gate FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
