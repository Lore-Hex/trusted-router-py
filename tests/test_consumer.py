"""Release contract tests build once, then use only a wheel in an external venv."""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.parser import BytesParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "__init__.py", "__main__.py", "_client_async.py", "_client_sync.py", "_collect.py",
    "_constants.py", "_errors.py", "_headers.py", "_orchestration.py", "_requests.py",
    "_retry.py", "_routing.py", "_sse.py", "_telemetry.py", "_transport.py",
    "attestation.py", "client.py", "models.py", "oauth.py", "py.typed", "receipts.py", "session.py",
}
DIST = "trusted_router_py-0.7.0"
UV = shutil.which("uv") or str(Path.home() / ".local/bin/uv")


def run(argv: list[str], cwd: Path, *, env: dict[str, str] | None = None,
        stdin: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- Test-owned argv, no shell.
        argv, cwd=cwd, env=env, input=stdin, text=True, capture_output=True,
        timeout=120, check=False,
    )


def require_success(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


@dataclass
class Installed:
    root: Path
    wheel: Path
    sdist: Path
    env: dict[str, str]

    @property
    def python(self) -> str:
        return str(self.root / "venv/bin/python")

    def call(self, args: list[str], *, env: dict[str, str] | None = None,
             stdin: str = "") -> subprocess.CompletedProcess[str]:
        return run(args, self.root, env=self.env | (env or {}), stdin=stdin)


@pytest.fixture(scope="session")
def installed() -> Iterator[Installed]:
    # Explicit stdlib temp directory: pytest --basetemp cannot put the consumer in the repo.
    with tempfile.TemporaryDirectory(prefix="trustedrouter-consumer-") as temporary:
        root = Path(temporary).resolve()
        assert ROOT not in root.parents
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("PYTHON", "TR_", "TRUSTEDROUTER", "CONSUMER_"))}
        env["UV_CACHE_DIR"] = os.environ.get("UV_CACHE_DIR", str(root / "uv-cache"))
        env["DO_NOT_TRACK"] = "1"
        require_success(run([UV, "build", "--out-dir", str(root / "dist")], ROOT, env=env))
        wheel = next((root / "dist").glob("*.whl"))
        sdist = next((root / "dist").glob("*.tar.gz"))
        require_success(run([UV, "venv", "--python", sys.executable, str(root / "venv")],
                            root, env=env))
        python = str(root / "venv/bin/python")
        require_success(run([UV, "pip", "install", "--python", python, str(wheel),
                             "mypy", "cryptography"], root, env=env))
        shutil.copyfile(ROOT / "tests/consumer/smoke.py", root / "smoke.py")
        # Only test fixtures live on PYTHONPATH; the library must resolve from site-packages.
        fixture = root / "fake"
        fixture.mkdir()
        shutil.copyfile(ROOT / "tests/consumer/sitecustomize.py", fixture / "sitecustomize.py")
        env.update(PYTHONPATH=str(fixture), TRUSTEDROUTER_API_KEY="fake",
                   TRUSTEDROUTER_BASE_URL="https://api.trustedrouter.com/v1",
                   CONSUMER_TLS_DOUBLE="1")
        yield Installed(root, wheel, sdist, env)


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
def test_artifact_listing(installed: Installed, artifact: str) -> None:
    if artifact == "wheel":
        with zipfile.ZipFile(installed.wheel) as wheel:
            names = wheel.namelist()
        expected = {f"trustedrouter/{name}" for name in SOURCES} | {
            f"{DIST}.dist-info/{name}" for name in
            ("METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE")
        }
    else:
        with tarfile.open(installed.sdist) as sdist:
            names = [entry.name for entry in sdist if entry.isfile()]
        expected = {f"{DIST}/src/trustedrouter/{name}" for name in SOURCES} | {
            f"{DIST}/{name}" for name in
            (".gitignore", "LICENSE", "README.md", "pyproject.toml", "PKG-INFO")
        }
    excluded = {"tests", "fixtures", "scripts", "docs", ".github", ".gitlab", ".circleci"}
    assert all(excluded.isdisjoint(Path(name).parts) for name in names)
    assert set(names) == expected
    assert len(names) == len(expected)


def test_artifact_metadata(installed: Installed) -> None:
    with zipfile.ZipFile(installed.wheel) as wheel:
        metadata = BytesParser().parsebytes(wheel.read(f"{DIST}.dist-info/METADATA"))
        assert metadata["Summary"] == "Official Python SDK and CLI for TrustedRouter."
        assert metadata["Requires-Python"] == ">=3.10"
        assert metadata["License-Expression"] == "Apache-2.0"
        assert metadata["License-File"] == "LICENSE"
        assert set(metadata["Keywords"].split(",")) == {
            "trustedrouter", "llm", "sdk", "attestation", "openai",
        }
        urls = dict(item.split(", ", 1) for item in metadata.get_all("Project-URL", []))
        assert urls == {
            "Homepage": "https://trustedrouter.com",
            "Documentation": "https://github.com/Lore-Hex/trusted-router-py#readme",
            "Issues": "https://github.com/Lore-Hex/trusted-router-py/issues",
            "Repository": "https://github.com/Lore-Hex/trusted-router-py",
            "Trust": "https://trust.trustedrouter.com",
        }
        classifiers = metadata.get_all("Classifier", [])
        assert "Typing :: Typed" in classifiers
        assert all(f"Programming Language :: Python :: 3.{v}" in classifiers for v in range(10, 15))
        assert "# TrustedRouter Python SDK" in metadata.get_payload()


def test_scratch_consumer(installed: Installed) -> None:
    # No source-tree or fake-transport path in this independently runnable consumer.
    env = installed.env | {"PYTHONPATH": "", "MYPYPATH": ""}
    origin = installed.call([installed.python, "-c",
                            "import trustedrouter; print(trustedrouter.__file__)"], env=env)
    require_success(origin)
    assert str(installed.root / "venv") in origin.stdout
    assert str(ROOT) not in origin.stdout
    require_success(installed.call(
        [installed.python, "-m", "mypy", "--strict", "smoke.py"], env=env,
    ))
    result = installed.call([installed.python, "smoke.py"], env=env)
    require_success(result)
    assert result.stdout == "installed consumer passed\n"


@dataclass
class Case:
    name: str
    args: list[str]
    marker: str
    code: int = 0
    stdin: str = ""
    env: dict[str, str] = field(default_factory=dict)
    command: str | None = None


CASES = [
    Case("version", ["--version"], "trustedrouter 0.7.0"),
    Case("version-json", ["--json", "--version"], "0.7.0", command="version"),
    Case("unknown", ["--json", "unknown"], "usage_error", 2),
    Case("missing-command", ["--json"], "usage_error", 2),
    Case("retries-invalid", ["--json", "--retries", "-1", "models"], "usage_error", 2),
    Case("missing-key", ["chat", "hello", "--json"], "authentication_error", 3,
         env={"TRUSTEDROUTER_API_KEY": ""}),
    Case("stdin", ["chat"], "hello consumer", stdin="hello\n"),
    Case("stdin-marker", ["chat", "-", "--json"], "hello consumer",
         stdin=" hello\n", command="chat"),
    Case("stdin-empty", ["chat", "--json"], "input_error", 2),
    Case("stdin-mixed", ["chat", "-", "hello", "--json"], "input_error", 2),
    Case("model-short", ["chat", "-m", "example/model", "hello"], "hello consumer"),
    Case("model-long", ["chat", "--model", "example/model", "--max-tokens", "7",
                        "hello", "--json"], "hello consumer", command="chat"),
    Case("model-empty", ["chat", "--model", " ", "--json", "hello"], "usage_error", 2),
    Case("tokens-invalid", ["chat", "--max-tokens", "0", "--json", "hello"], "usage_error", 2),
    Case("stream", ["chat", "--stream", "hello"], "hello consumer"),
    Case("stream-json", ["chat", "--stream", "--json", "hello"], "chat.done", command="stream"),
    Case("connect-without-session", ["attest", "--connect-ip", "127.0.0.1", "--json"],
         "usage_error", 2),
    Case("connect-empty", ["attest", "--session", "--connect-ip", "", "--json"],
         "usage_error", 2),
    Case("session-failure", ["attest", "--session", "--json"], "runtime_error", 1,
         env={"CONSUMER_SESSION_FAIL": "1"}),
    Case("retry-once", ["--retries", "1", "chat", "hello", "--json"], "hello consumer",
         env={"CONSUMER_STATUS": "500", "CONSUMER_RETRY": "1"}, command="chat"),
]
for command, args, marker in [
    ("chat", ["chat", "hello"], "hello consumer"),
    ("regions", ["regions"], "regions"),
    ("providers", ["providers"], "providers"),
    ("models", ["models"], "models"),
    ("trust", ["trust"], "sha256:consumer"),
    ("attest", ["attest"], "."),
    ("attest.verify", ["attest", "--verify"], "sha256:consumer"),
    ("attest.session", ["attest", "--session", "--connect-ip", "127.0.0.1"], "exporter"),
]:
    CASES.append(Case(command + "-plain", args, marker))
    CASES.append(Case(command + "-json", [*args, "--json"], marker, command=command))
    CASES.append(Case(command + "-global-json", ["--json", *args], marker, command=command))
    if command != "attest.session":
        for status, code, error in [(401, 3, "authentication_error"), (500, 1, "internal_error")]:
            # Raw attestation currently raises the base SDK error for HTTP failures.
            if command.startswith("attest"):
                code, error = 1, "trusted_router_error"
            CASES.append(Case(f"{command}-{status}", ["--retries", "0", *args, "--json"],
                              error, code, env={"CONSUMER_STATUS": str(status)}))
for command in ("", "chat", "regions", "providers", "models", "trust", "attest"):
    for help_option in ("-h", "--help"):
        CASES.append(Case(f"help-{command or 'root'}-{help_option}",
                          ([command] if command else []) + [help_option], "usage:"))


@pytest.mark.parametrize("entry", ["module", "script"])
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_installed_cli(installed: Installed, entry: str, case: Case) -> None:
    executable = ([installed.python, "-m", "trustedrouter"] if entry == "module"
                  else [str(installed.root / "venv/bin/trustedrouter")])
    log = installed.root / "requests.jsonl"
    log.unlink(missing_ok=True)
    result = installed.call(executable + case.args,
                            env=case.env | {"CONSUMER_REQUEST_LOG": str(log)}, stdin=case.stdin)
    expected_code = case.code
    expected_marker = case.marker
    assert result.returncode == expected_code, result.stdout + result.stderr
    output = result.stderr if case.code else result.stdout
    assert expected_marker in output
    if "--json" in case.args:
        records = [json.loads(line) for line in output.splitlines()]
        assert records
        assert not (result.stdout if case.code else result.stderr)
        if case.code:
            assert len(records) == 1
            assert records[0]["ok"] is False
            assert isinstance(records[0]["error"]["message"], str)
            assert records[0]["error"]["type"] == case.marker
        elif case.command == "stream":
            assert records == [
                {"ok": True, "command": "chat.delta", "data": {"text": "hello consumer"}},
                {"ok": True, "command": "chat.done", "data": None},
            ]
        else:
            assert len(records) == 1
            assert set(records[0]) == {"ok", "command", "data"}
            assert records[0]["ok"] is True
            assert records[0]["command"] == case.command
            data = records[0]["data"]
            if case.command == "chat":
                assert data["choices"][0]["message"]["content"] == "hello consumer"
            elif case.command in ("models", "regions", "providers"):
                assert data["data"][0]["id"] == case.command
            elif case.command == "attest":
                assert len(data["document"].split(".")) == 3
            elif case.command == "attest.session":
                assert set(data) == {"attestation", "followup", "exporter"}
                assert data["attestation"] == data["followup"]
                assert data["exporter"] == b"exporter".hex()
            elif case.command in ("trust", "attest.verify"):
                assert data["image_digest"] == "sha256:consumer"
    if case.name in ("model-short", "model-long", "stdin-marker", "retry-once"):
        requests = [json.loads(line) for line in log.read_text().splitlines()]
        body = json.loads(requests[-1]["body"])
        if case.name.startswith("model-"):
            assert body["model"] == "example/model"
        if case.name == "model-long":
            assert body["max_tokens"] == 7
        if case.name == "stdin-marker":
            assert body["messages"][0]["content"] == case.stdin
        if case.name == "retry-once":
            assert len(requests) == 2


def examples() -> list[tuple[str, str, str]]:
    found = []
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        for match in re.finditer(r"^```([^\n]*)\n(.*?)^```\s*$", path.read_text(), re.M | re.S):
            line = path.read_text()[:match.start()].count("\n") + 1
            found.append((f"{path.relative_to(ROOT)}:{line}", match[1], match[2]))
    return found


@pytest.mark.parametrize("location,language,source", examples(), ids=lambda value: value[:80])
def test_documented_examples(
    installed: Installed, location: str, language: str, source: str,
) -> None:
    if language == "python":
        compile(source, location, "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
        prelude = """import asyncio
from types import SimpleNamespace
from trustedrouter import TrustedRouter, AUTO_MODEL
import sitecustomize
client = TrustedRouter(api_key="fake")
resp = client.chat_completions(messages=[{"role": "user", "content": "hello"}])
user_id, order_id = "user", "order"
redirect_to = lambda url: None
store_for_user = lambda key, identity: None
request = SimpleNamespace(args={"code": "fake"})
saved_verifier = "v" * 64
receipt_jws = sitecustomize.receipt()
serialized_request, response_bytes, request_nonce = b"request", b"response", "nonce_test"
async def my_cert_pin_hook(response):
    pass
"""
        runner = installed.root / "example.py"
        # Wrap only blocks that actually have top-level await, preserving asyncio.run examples.
        tree = ast.parse(source)
        if any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Await)
               for node in tree.body):
            source = "async def example():\n" + "".join(
                "    " + line + "\n" for line in source.splitlines()
            ) + "\nasyncio.run(example())\n"
        runner.write_text(prelude + source + "\n")
        require_success(installed.call([installed.python, str(runner)]))
    elif language in ("sh", "bash"):
        # Installation/development commands are syntax checked, never recursively executed.
        require_success(installed.call(["/bin/bash", "-n"], stdin=source))
    elif language == "json":
        json.loads(source)
    else:
        pytest.fail(f"Unvalidated documentation language {language!r} at {location}")
