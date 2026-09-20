"""Prove consumer release guards fail, without modifying the worktree."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = "tests/test_consumer.py::test_installed_cli"
DOCS = "tests/test_consumer.py::test_documented_examples"


def pytest(root: Path, target: str, *, failures: bool = False, every: bool = False) -> int:
    env = dict(os.environ, PYTHONPATH=str(root / "src"), PYTHONDONTWRITEBYTECODE="1")
    report = root / "results.xml"
    result = subprocess.run(  # noqa: S603 -- Fixed test command, no shell.
        [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", "--no-cov",
         "--junitxml", str(report), target],
        cwd=root, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    # This XML was just emitted by our own pytest subprocess in a private directory.
    cases = ET.parse(report).findall(".//testcase")  # noqa: S314 -- Trusted local report.
    if not failures:
        if result.returncode:
            raise ValueError(f"Baseline failed:\n{result.stdout}\n{result.stderr}")
        return len(cases)
    failed = [case for case in cases if case.find("failure") is not None]
    if (result.returncode != 1 or not failed or
            any(case.find("error") is not None for case in cases) or
            (every and len(failed) != len(cases))):
        raise ValueError(f"Invalid mutation proof:\n{result.stdout}\n{result.stderr}")
    if every:
        for case in failed:
            print(f"  REJECTED {case.attrib['name']}", flush=True)
    return len(failed)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="trustedrouter-consumer-mutations-") as temporary:
        root = Path(temporary)
        for name in ("src", "tests", "docs"):
            shutil.copytree(ROOT / name, root / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("README.md", "LICENSE", "pyproject.toml", ".gitignore"):
            shutil.copyfile(ROOT / name, root / name)
        count = pytest(root, "tests/test_consumer.py")
        print(f"BASELINE {count} consumer checks passed", flush=True)
        mutations = [
            ("artifact-stray", "src/trustedrouter/stray.txt", None, "scratch must not ship",
             "tests/test_consumer.py::test_artifact_listing", True),
            ("metadata-keywords", "pyproject.toml", '"trustedrouter", "llm", "sdk"',
             '"trustedrouter", "llm"', "tests/test_consumer.py::test_artifact_metadata", False),
            ("typed-marker", "src/trustedrouter/py.typed", None, None,
             "tests/test_consumer.py::test_scratch_consumer", False),
            ("consumer-type", "tests/consumer/smoke.py", "content: str | None",
             "content: int", "tests/test_consumer.py::test_scratch_consumer", False),
            ("consumer-runtime", "tests/consumer/smoke.py", 'assert content == "hello consumer"',
             'assert content == "wrong response"', "tests/test_consumer.py::test_scratch_consumer",
             False),
            ("readme-python", "README.md", "resp = client.chat_completions(",
             "resp = client.nonexistent_method(", DOCS, False),
            ("readme-shell", "README.md", "pip install trusted-router-py ",
             'pip install "trusted-router-py ', DOCS, False),
            ("readme-json", "README.md", '"id":"chatcmpl-example"', '"id":invalid', DOCS, False),
            ("cli-exit-every-case", "tests/test_consumer.py", "expected_code = case.code",
             "expected_code = case.code + 99", CLI, True),
            ("cli-output-every-case", "tests/test_consumer.py", "expected_marker = case.marker",
             'expected_marker = "WRONG-OUTPUT-SHAPE"', CLI, True),
        ]
        metadata_changes = [
            ("description", 'description = "Official Python SDK and CLI for TrustedRouter."',
             'description = "wrong description"'),
            ("minimum-python", 'requires-python = ">=3.10"', 'requires-python = ">=3.9"'),
            ("license", 'license = "Apache-2.0"', 'license = "MIT"'),
            ("license-file", 'license-files = ["LICENSE"]', 'license-files = []'),
            ("typing-classifier", '  "Typing :: Typed",', ""),
        ]
        project_text = (root / "pyproject.toml").read_text()
        for url in ("Homepage", "Documentation", "Issues", "Repository", "Trust"):
            line = next(line for line in project_text.splitlines() if line.startswith(url + " ="))
            metadata_changes.append((url.lower() + "-url", line, f'{url} = "https://invalid.test"'))
        for version in range(10, 15):
            metadata_changes.append((f"python-3.{version}",
                                     f'  "Programming Language :: Python :: 3.{version}",', ""))
        for name, before, after in metadata_changes:
            mutations.append((f"metadata-{name}", "pyproject.toml", before, after,
                              "tests/test_consumer.py::test_artifact_metadata", False))
        mutations.extend([
            ("metadata-readme", "README.md", "# TrustedRouter Python SDK",
             "# Wrong README", "tests/test_consumer.py::test_artifact_metadata", False),
            ("consumer-docstrings", "tests/consumer/smoke.py",
             "assert client.chat_completions.__doc__", "assert not client.chat_completions.__doc__",
             "tests/test_consumer.py::test_scratch_consumer", False),
        ])
        for name, filename, before, after, target, every in mutations:
            path = root / filename
            original = path.read_bytes() if path.exists() else None
            try:
                if before is None:
                    if after is None:
                        path.unlink()
                    else:
                        path.write_text(after)
                else:
                    assert original is not None
                    text = original.decode()
                    if text.count(before) != 1:
                        raise ValueError(f"STALE mutation: {name}")
                    path.write_text(text.replace(before, after, 1))
                print(f"MUTATING {name}", flush=True)
                count = pytest(root, target, failures=True, every=every)
                print(f"KILLED {name}: {count} assertion failures", flush=True)
            finally:
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(original)
                assert (path.read_bytes() if path.exists() else None) == original
        print("All consumer mutations killed; all original bytes restored.", flush=True)


if __name__ == "__main__":
    main()
