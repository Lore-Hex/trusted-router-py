"""Coverage for the trustedrouter CLI. We don't drive a real network
here — the gateway-talking commands are exercised by patching the
TrustedRouter class so they go through MockTransport. The goal is to
prove parser routing + exit codes + error formatting, not to
re-validate the SDK itself."""
from __future__ import annotations

import httpx
import pytest

from trustedrouter import TrustedRouter, __version__
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


def test_regions_invalid_choice_rejected_by_argparse(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--region", "mars", "regions"])
    err = capsys.readouterr().err
    assert "invalid choice" in err


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
