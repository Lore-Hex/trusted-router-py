"""Coverage for the trustedrouter CLI. We don't drive a real network
here — the gateway-talking commands are exercised by patching the
TrustedRouter class so they go through MockTransport. The goal is to
prove parser routing + exit codes + error formatting, not to
re-validate the SDK itself."""
from __future__ import annotations

import argparse
import io
import json

import httpx
import pytest

from trustedrouter import InternalError, TrustedRouter, __version__
from trustedrouter import __main__ as cli


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # type: ignore[no-untyped-def]
    """Make `cli._client` return a TrustedRouter that goes through the
    given mock handler instead of the real network."""

    def fake_client(args):  # type: ignore[no-untyped-def]
        return TrustedRouter(
            api_key="cli-test-key",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            max_retries=0,
        )

    monkeypatch.setattr(cli, "_client", fake_client)
    monkeypatch.setattr(cli, "_bearer", lambda: "cli-test-key")


def test_help_and_version_strings(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    assert "TrustedRouter CLI v" in out
    assert __version__ in out


def test_chat_command_prints_completion_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"PONG"},'
                    b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        )

    _patch_client(monkeypatch, handler)
    rc = cli.main(["chat", "say", "PONG"])
    assert rc == 0
    assert "PONG" in capsys.readouterr().out


def test_chat_command_streaming_mode(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"a "}}]}\n\n'
                    b'data: {"choices":[{"delta":{"content":"b"}}]}\n\n'
                    b"data: [DONE]\n\n",
        )

    _patch_client(monkeypatch, handler)
    rc = cli.main(["chat", "--stream", "x"])
    assert rc == 0
    assert "a b" in capsys.readouterr().out


def test_chat_auth_error_returns_code_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid"}})

    _patch_client(monkeypatch, handler)
    rc = cli.main(["chat", "x"])
    assert rc == 3
    assert "TRUSTEDROUTER_API_KEY" in capsys.readouterr().err


def test_chat_missing_key_is_rejected_locally_before_client(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("TRUSTEDROUTER_API_KEY", raising=False)
    monkeypatch.delenv("TR_API_KEY", raising=False)
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before client")),
    )

    assert cli.main(["chat", "hello", "--json"]) == cli.EXIT_AUTH
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "authentication_error",
            "message": "no API key found; set TRUSTEDROUTER_API_KEY (or TR_API_KEY)",
        },
    }


def test_chat_other_error_returns_code_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "boom"}})

    _patch_client(monkeypatch, handler)
    rc = cli.main(["chat", "x"])
    assert rc == 1
    assert "HTTP 500" in capsys.readouterr().err


@pytest.mark.parametrize("subcmd,path", [
    ("regions", "/v1/regions"),
    ("providers", "/v1/providers"),
    ("models", "/v1/models"),
])
def test_list_subcommands_hit_correct_paths(
    subcmd: str, path: str,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"data": [{"id": subcmd}]})

    _patch_client(monkeypatch, handler)
    rc = cli.main([subcmd])
    assert rc == 0
    assert seen == [path]
    assert subcmd in capsys.readouterr().out


def test_unknown_subcommand_exits_nonzero() -> None:
    with pytest.raises(SystemExit):
        cli.main(["frobnicate"])


def test_chat_empty_prompt_returns_code_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Argparse requires nargs+, but a single empty arg sneaks past
    that. The handler should reject it with code 2."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    _patch_client(monkeypatch, handler)
    rc = cli.main(["chat", ""])
    assert rc == 2


def test_bearer_resolution_prefers_TRUSTEDROUTER_API_KEY_over_TR_API_KEY(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRUSTEDROUTER_API_KEY", "tr-pref")
    monkeypatch.setenv("TR_API_KEY", "tr-fallback")
    assert cli._bearer() == "tr-pref"

    monkeypatch.delenv("TRUSTEDROUTER_API_KEY")
    assert cli._bearer() == "tr-fallback"

    monkeypatch.delenv("TR_API_KEY")
    assert cli._bearer() is None


def test_attest_raw_prints_jwt_bytes_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<JWT-BYTES>")

    _patch_client(monkeypatch, handler)
    rc = cli.main(["attest"])
    assert rc == 0
    assert capsysbinary.readouterr().out == b"<JWT-BYTES>"


def test_trust_command_success_and_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "fetch_trust_release", lambda: {"image_digest": "sha256:test"})
    assert cli.main(["trust"]) == 0
    assert "sha256:test" in capsys.readouterr().out

    def fail() -> object:
        raise RuntimeError("trust unavailable")

    monkeypatch.setattr(cli, "fetch_trust_release", fail)
    assert cli.main(["trust"]) == 1
    assert "trust unavailable" in capsys.readouterr().err


def test_attest_verify_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeResult:
        def as_dict(self) -> dict[str, str]:
            return {"status": "verified"}

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<JWT>")

    def fake_verify(
        document: bytes,
        *,
        policy: object,
    ) -> FakeResult:
        assert document == b"<JWT>"
        assert policy == {"policy": "ok"}
        return FakeResult()

    _patch_client(monkeypatch, handler)
    import trustedrouter.attestation as attestation

    monkeypatch.setattr(attestation, "policy_from_trust_release", lambda: {"policy": "ok"})
    monkeypatch.setattr(attestation, "verify_gateway_attestation", fake_verify)

    rc = cli.main(["attest", "--verify", "--json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "command": "attest.verify",
        "data": {"status": "verified"},
    }


def test_attest_verify_error_returns_code_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<JWT>")

    _patch_client(monkeypatch, handler)
    import trustedrouter.attestation as attestation

    monkeypatch.setattr(attestation, "policy_from_trust_release", lambda: {"policy": "ok"})
    monkeypatch.setattr(
        attestation,
        "verify_gateway_attestation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("verification failed")),
    )
    rc = cli.main(["attest", "--verify"])
    assert rc == 1
    assert "verification failed" in capsys.readouterr().err


def test_attest_session_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("session mode must not fetch attestation over httpx")

    class FakeAttestation:
        cert_sha256 = "c" * 64
        image_digest = "sha256:test"

        def as_dict(self) -> dict[str, str]:
            return {
                "cert_sha256": self.cert_sha256,
                "image_digest": self.image_digest,
            }

    class FakeConnection:
        def shutdown(self) -> None:
            return None

        def close(self) -> None:
            return None

    class FakeSession:
        attestation = FakeAttestation()
        connection = FakeConnection()
        exporter = bytes.fromhex("ab" * 32)

    def fake_verify_gateway_session(
        *,
        base_url: str,
        policy: object,
        connect_ip: str | None,
    ) -> FakeSession:
        assert base_url == "https://api.trustedrouter.com/v1"
        assert policy == {"policy": "ok"}
        assert connect_ip == "127.0.0.1"
        return FakeSession()

    def fake_fetch_attestation_again(session: FakeSession) -> FakeAttestation:
        assert isinstance(session, FakeSession)
        return FakeAttestation()

    _patch_client(monkeypatch, handler)
    import trustedrouter.attestation as attestation
    import trustedrouter.session as session_mod

    monkeypatch.setattr(attestation, "policy_from_trust_release", lambda: {"policy": "ok"})
    monkeypatch.setattr(session_mod, "verify_gateway_session", fake_verify_gateway_session)
    monkeypatch.setattr(session_mod, "fetch_attestation_again", fake_fetch_attestation_again)

    rc = cli.main(["attest", "--session", "--connect-ip", "127.0.0.1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "attestation verified" in out
    assert "follow-up /attestation stayed" in out

    rc = cli.main([
        "attest", "--session", "--connect-ip", "127.0.0.1", "--json",
    ])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["command"] == "attest.session"


@pytest.mark.parametrize("argv", [["--version"], ["--json", "--version"]])
def test_version_flag_supports_plain_and_json(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    assert raised.value.code == cli.EXIT_SUCCESS
    out = capsys.readouterr().out
    if "--json" in argv:
        assert json.loads(out) == {
            "ok": True,
            "command": "version",
            "data": {"version": __version__},
        }
    else:
        assert out == f"trustedrouter {__version__}\n"


@pytest.mark.parametrize("literal_prompt", ["--json", "--version"])
def test_option_like_prompt_after_terminator_remains_literal(
    literal_prompt: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen_prompts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_prompts.append(json.loads(request.content)["messages"][0]["content"])
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"PONG"},'
                    b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        )

    _patch_client(monkeypatch, handler)
    assert cli.main(["chat", "--", literal_prompt]) == cli.EXIT_SUCCESS
    assert seen_prompts == [literal_prompt]
    assert capsys.readouterr().out == "PONG\n"


@pytest.mark.parametrize("argv", [["chat", "-"], ["chat"]])
def test_chat_reads_explicit_or_implicit_stdin(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen_prompts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_prompts.append(body["messages"][0]["content"])
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"PONG"},'
                    b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        )

    _patch_client(monkeypatch, handler)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("  prompt from stdin\n"))

    assert cli.main(argv) == cli.EXIT_SUCCESS
    assert seen_prompts == ["  prompt from stdin\n"]
    assert capsys.readouterr().out == "PONG\n"


def test_chat_rejects_ambiguous_or_empty_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))

    assert cli.main(["chat", "text", "-"]) == cli.EXIT_USAGE
    assert "cannot be combined" in capsys.readouterr().err

    assert cli.main(["--json", "chat"]) == cli.EXIT_USAGE
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "ok": False,
        "error": {"type": "input_error", "message": "prompt must not be empty"},
    }


def test_chat_json_returns_full_completion_envelope(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"id":"chat-1","model":"trustedrouter/auto",'
                    b'"choices":[{"index":0,"delta":{"content":"PONG"},'
                    b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        )

    _patch_client(monkeypatch, handler)
    assert cli.main(["chat", "--json", "ping"]) == cli.EXIT_SUCCESS

    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["command"] == "chat"
    assert result["data"]["choices"][0]["message"]["content"] == "PONG"
    assert result["data"]["id"] == "chat-1"


def test_streaming_chat_json_is_deterministic_json_lines(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"a "}}]}\n\n'
                    b'data: {"choices":[{"delta":{"content":"b"}}]}\n\n'
                    b"data: [DONE]\n\n",
        )

    _patch_client(monkeypatch, handler)
    assert cli.main(["--json", "chat", "--stream", "x"]) == cli.EXIT_SUCCESS

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert records == [
        {"ok": True, "command": "chat.delta", "data": {"text": "a "}},
        {"ok": True, "command": "chat.delta", "data": {"text": "b"}},
        {"ok": True, "command": "chat.done", "data": None},
    ]


@pytest.mark.parametrize("argv", [["--json", "models"], ["models", "--json"]])
def test_json_flag_works_before_or_after_subcommand(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "model-a"}]})

    _patch_client(monkeypatch, handler)
    assert cli.main(argv) == cli.EXIT_SUCCESS
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["command"] == "models"
    assert result["data"]["data"][0]["id"] == "model-a"


def test_json_errors_are_single_stderr_records_with_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def auth_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": "invalid", "request_id": "req-auth"}},
        )

    _patch_client(monkeypatch, auth_handler)
    assert cli.main(["--json", "models"]) == cli.EXIT_AUTH
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "ok": False,
        "error": {
            "type": "authentication_error",
            "message": "invalid",
            "status_code": 401,
            "request_id": "req-auth",
        },
    }

    def api_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "unavailable"}})

    _patch_client(monkeypatch, api_handler)
    assert cli.main(["--json", "models"]) == cli.EXIT_RUNTIME
    error = json.loads(capsys.readouterr().err)
    assert error["error"] == {
        "type": "internal_error",
        "message": "unavailable",
        "status_code": 503,
    }


def test_json_usage_errors_do_not_mix_usage_text_into_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["--json", "frobnicate"])
    assert raised.value.code == cli.EXIT_USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)
    assert error["ok"] is False
    assert error["error"]["type"] == "usage_error"
    assert "invalid choice" in error["error"]["message"]


def test_attest_json_wraps_raw_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"header.payload.signature")

    _patch_client(monkeypatch, handler)
    assert cli.main(["attest", "--json"]) == cli.EXIT_SUCCESS
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "command": "attest",
        "data": {"document": "header.payload.signature"},
    }


def test_stdin_prompt_is_bounded_before_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "MAX_STDIN_PROMPT_BYTES", 8)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("123456789"))
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )

    assert cli.main(["chat", "--json"]) == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "input_error",
            "message": "stdin prompt exceeds 8 MiB limit",
        },
    }


def test_invalid_utf8_stdin_is_a_structured_input_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stdin = io.TextIOWrapper(io.BytesIO(b"\xff"), encoding="utf-8", errors="strict")
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )

    assert cli.main(["chat", "--json"]) == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "input_error",
            "message": "stdin prompt must be valid UTF-8",
        },
    }


def test_non_utf8_text_wrapper_cannot_transcode_invalid_raw_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stdin = io.TextIOWrapper(io.BytesIO(b"\xff"), encoding="cp1252", errors="strict")
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before client")),
    )

    assert cli.main(["chat", "--json"]) == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "input_error",
            "message": "stdin prompt must be valid UTF-8",
        },
    }


@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "--retries", "-1", "models"],
        ["chat", "--json", "--max-tokens", "0", "hello"],
    ],
)
def test_invalid_numeric_options_exit_before_network(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )

    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    assert raised.value.code == cli.EXIT_USAGE
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["type"] == "usage_error"
    assert "must be at least" in error["error"]["message"]


@pytest.mark.parametrize("model", ["", "   "])
def test_empty_model_exits_before_client_construction(
    model: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )

    with pytest.raises(SystemExit) as raised:
        cli.main(["chat", "hello", "--model", model, "--json"])
    assert raised.value.code == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {"type": "usage_error", "message": "--model cannot be empty"},
    }


def test_permission_denied_uses_auth_exit_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"error": {"message": "scope denied", "request_id": "req-scope"}},
        )

    _patch_client(monkeypatch, handler)
    assert cli.main(["models", "--json"]) == cli.EXIT_AUTH
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "permission_denied_error",
            "message": "scope denied",
            "status_code": 403,
            "request_id": "req-scope",
        },
    }


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["attest", "--connect-ip", "127.0.0.1", "--json"], "requires --session"),
        (["attest", "--session", "--connect-ip", "", "--json"], "must not be empty"),
    ],
)
def test_connect_ip_requires_session_and_a_nonempty_value(
    argv: list[str],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before network")),
    )

    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    assert raised.value.code == cli.EXIT_USAGE
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["type"] == "usage_error"
    assert message in error["error"]["message"]


def test_trust_sdk_errors_keep_the_cross_runtime_type(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail() -> object:
        raise InternalError(503, "trust unavailable", payload={})

    monkeypatch.setattr(cli, "fetch_trust_release", fail)
    assert cli.main(["trust", "--json"]) == cli.EXIT_RUNTIME
    assert json.loads(capsys.readouterr().err) == {
        "ok": False,
        "error": {
            "type": "internal_error",
            "message": "trust unavailable",
            "status_code": 503,
        },
    }


def test_client_honors_agent_environment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, object]] = []

    def fake_client(**kwargs: object) -> object:
        seen.append(kwargs)
        return object()

    monkeypatch.setattr(cli, "TrustedRouter", fake_client)
    monkeypatch.setenv("TRUSTEDROUTER_API_KEY", "sk-tr-primary")
    monkeypatch.setenv("TRUSTEDROUTER_BASE_URL", "https://inference.example/v1")
    monkeypatch.setenv("TR_BASE_URL", "https://fallback.example/v1")
    monkeypatch.setenv("TRUSTEDROUTER_CONTROL_BASE_URL", "https://control.example/v1")
    monkeypatch.setenv("TRUSTEDROUTER_WORKSPACE_ID", "ws_agent")

    cli._client(argparse.Namespace(retries=4))
    assert seen == [
        {
            "api_key": "sk-tr-primary",
            "base_url": "https://inference.example/v1",
            "control_base_url": "https://control.example/v1",
            "workspace_id": "ws_agent",
            "max_retries": 4,
        }
    ]

    monkeypatch.delenv("TRUSTEDROUTER_BASE_URL")
    cli._client(argparse.Namespace(retries=0))
    assert seen[-1]["base_url"] == "https://fallback.example/v1"


@pytest.mark.parametrize("command", ["chat", "models", "attest"])
def test_client_construction_errors_follow_json_runtime_contract(
    command: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_client(_args: argparse.Namespace) -> TrustedRouter:
        raise ValueError("invalid base URL")

    monkeypatch.setattr(cli, "_client", fail_client)
    monkeypatch.setattr(cli, "_bearer", lambda: "cli-test-key")
    argv = ["--json", command]
    if command == "chat":
        argv.append("hello")

    assert cli.main(argv) == cli.EXIT_RUNTIME
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "ok": False,
        "error": {"type": "runtime_error", "message": "invalid base URL"},
    }
