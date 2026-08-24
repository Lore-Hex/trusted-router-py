"""Official TrustedRouter CLI for developers, agents, and gateway diagnostics.

Usage:
  trustedrouter chat "hello"          # one-shot completion (uses AUTO_MODEL)
  echo "hello" | trustedrouter chat   # read the prompt from stdin
  trustedrouter chat -m claude "hi"   # specify model
  trustedrouter regions               # list deployed regions
  trustedrouter providers             # list provider catalog
  trustedrouter models                # list model catalog
  trustedrouter attest                # fetch raw attestation JWT
  trustedrouter attest --verify       # fetch + verify against trust release
  trustedrouter trust                 # show the published trust release

Reads bearer from $TRUSTEDROUTER_API_KEY (or $TR_API_KEY). Plain mode preserves
the original text/JSON output. ``--json`` emits stable envelopes suitable for
agents and shell pipelines; streaming chat uses JSON Lines."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from contextlib import suppress
from typing import Any, NoReturn, TextIO

from trustedrouter import (
    AUTO_MODEL,
    AuthenticationError,
    PermissionDeniedError,
    TrustedRouter,
    TrustedRouterError,
    __version__,
    fetch_trust_release,
)

EXIT_SUCCESS = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
MAX_STDIN_PROMPT_BYTES = 8 * 1024 * 1024


def _jsonable(value: object) -> object:
    """Convert SDK models into JSON-native values without losing extensions."""

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json")
        except TypeError:
            # Tests and third-party response models may expose a compatible
            # model_dump() without pydantic's ``mode`` keyword.
            return dump()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _write_json(value: object, *, file: TextIO | None = None) -> None:
    """Write one deterministic, compact JSON record."""

    print(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ),
        file=file or sys.stdout,
    )


def _emit_success(command: str, data: object) -> None:
    _write_json({"ok": True, "command": command, "data": _jsonable(data)})


def _emit_error(
    args: argparse.Namespace | None,
    *,
    error_type: str,
    message: str,
    exit_code: int,
    plain_message: str | None = None,
    status_code: int | None = None,
    request_id: str | None = None,
    json_mode: bool | None = None,
) -> int:
    use_json = bool(getattr(args, "json", False)) if json_mode is None else json_mode
    if use_json:
        error: dict[str, object] = {"type": error_type, "message": message}
        if status_code is not None:
            error["status_code"] = status_code
        if request_id:
            error["request_id"] = request_id
        _write_json({"ok": False, "error": error}, file=sys.stderr)
    else:
        print(plain_message or f"error: {message}", file=sys.stderr)
    return exit_code


class _CLIArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that keeps usage errors machine-readable in JSON mode."""

    def __init__(self, *args: Any, json_mode: bool = False, **kwargs: Any) -> None:
        self.json_mode = json_mode
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        if self.json_mode:
            _emit_error(
                None,
                error_type="usage_error",
                message=message,
                exit_code=EXIT_USAGE,
                json_mode=True,
            )
            self.exit(EXIT_USAGE)
        super().error(message)


class _VersionAction(argparse.Action):
    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: object = argparse.SUPPRESS,
        help: str | None = None,
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            required=False,
            help=help,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        del namespace, values, option_string
        if isinstance(parser, _CLIArgumentParser) and parser.json_mode:
            _emit_success("version", {"version": __version__})
        else:
            print(f"trustedrouter {__version__}")
        parser.exit(EXIT_SUCCESS)


class _CLIInputError(ValueError):
    pass


def _bearer() -> str | None:
    return (
        os.environ.get("TRUSTEDROUTER_API_KEY")
        or os.environ.get("TR_API_KEY")
        or None
    )


def _client(args: argparse.Namespace) -> TrustedRouter:
    return TrustedRouter(
        api_key=_bearer(),
        base_url=(
            os.environ.get("TRUSTEDROUTER_BASE_URL")
            or os.environ.get("TR_BASE_URL")
            or None
        ),
        control_base_url=os.environ.get("TRUSTEDROUTER_CONTROL_BASE_URL") or None,
        workspace_id=os.environ.get("TRUSTEDROUTER_WORKSPACE_ID") or None,
        max_retries=args.retries,
    )


def _print(value: object) -> None:
    # Pydantic models expose model_dump(); fall back to json.dumps for
    # plain dicts/lists; everything else stringifies.
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        print(json.dumps(dump(), indent=2, default=str))
    elif isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2))
    else:
        print(value)


def _stdin_prompt() -> str:
    raw_stdin = getattr(sys.stdin, "buffer", None)
    try:
        if raw_stdin is not None:
            byte_chunks: list[bytes] = []
            byte_count = 0
            while byte_count <= MAX_STDIN_PROMPT_BYTES:
                chunk = raw_stdin.read(
                    min(64 * 1024, MAX_STDIN_PROMPT_BYTES - byte_count + 1)
                )
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > MAX_STDIN_PROMPT_BYTES:
                    raise _CLIInputError("stdin prompt exceeds 8 MiB limit")
                byte_chunks.append(chunk)
            return b"".join(byte_chunks).decode("utf-8", errors="strict")

        # StringIO and other in-memory text streams used by embedders/tests do
        # not expose ``buffer``. Preserve that safe fallback while continuing
        # to enforce the byte limit against their UTF-8 representation.
        text_chunks: list[str] = []
        byte_count = 0
        while byte_count <= MAX_STDIN_PROMPT_BYTES:
            chunk = sys.stdin.read(
                min(64 * 1024, MAX_STDIN_PROMPT_BYTES - byte_count + 1)
            )
            if not chunk:
                break
            byte_count += len(chunk.encode("utf-8", errors="strict"))
            if byte_count > MAX_STDIN_PROMPT_BYTES:
                raise _CLIInputError("stdin prompt exceeds 8 MiB limit")
            text_chunks.append(chunk)
        return "".join(text_chunks)
    except UnicodeError as exc:
        raise _CLIInputError("stdin prompt must be valid UTF-8") from exc
    except OSError as exc:
        raise _CLIInputError("prompt is required (pass text or pipe stdin)") from exc


def _prompt_from_args(args: argparse.Namespace) -> str:
    prompt_parts = list(args.prompt)
    if "-" in prompt_parts and prompt_parts != ["-"]:
        raise _CLIInputError("prompt '-' cannot be combined with positional prompt text")

    if prompt_parts and prompt_parts != ["-"]:
        prompt = " ".join(prompt_parts)
    else:
        isatty = getattr(sys.stdin, "isatty", None)
        if not prompt_parts and callable(isatty) and isatty():
            raise _CLIInputError("prompt is required (pass text or pipe stdin)")
        prompt = _stdin_prompt()

    if not prompt.strip():
        raise _CLIInputError("prompt must not be empty")
    return prompt


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be at least 0")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _sdk_error_type(exc: TrustedRouterError) -> str:
    """Return the cross-runtime snake_case SDK exception name."""

    return re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).lower()


def _cmd_chat(args: argparse.Namespace) -> int:
    try:
        prompt = _prompt_from_args(args)
    except _CLIInputError as exc:
        message = str(exc)
        return _emit_error(
            args,
            error_type="input_error",
            message=message,
            exit_code=EXIT_USAGE,
            plain_message="error: empty prompt" if message == "prompt must not be empty" else None,
        )

    if _bearer() is None:
        return _emit_error(
            args,
            error_type="authentication_error",
            message="no API key found; set TRUSTEDROUTER_API_KEY (or TR_API_KEY)",
            exit_code=EXIT_AUTH,
        )

    client: TrustedRouter | None = None
    try:
        client = _client(args)
        if args.stream:
            for tok in client.chat_completions_stream(
                model=args.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=args.max_tokens,
            ):
                if args.json:
                    if tok:
                        _emit_success("chat.delta", {"text": tok})
                else:
                    print(tok, end="", flush=True)
            if args.json:
                _emit_success("chat.done", None)
            else:
                print()
            return EXIT_SUCCESS
        resp = client.chat_completions(
            model=args.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=args.max_tokens,
        )
        if args.json:
            _emit_success("chat", resp)
        else:
            print(resp.choices[0].message.content or "")
        return EXIT_SUCCESS
    except (AuthenticationError, PermissionDeniedError) as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_AUTH,
            plain_message=(
                f"error: {exc} (set TRUSTEDROUTER_API_KEY)"
                if isinstance(exc, AuthenticationError)
                else f"error: HTTP {exc.status_code}: {exc}"
            ),
        )
    except TrustedRouterError as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_RUNTIME,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return _emit_error(
            args,
            error_type="runtime_error",
            message=str(exc),
            exit_code=EXIT_RUNTIME,
        )
    finally:
        if client is not None:
            with suppress(Exception):
                client.close()


def _cmd_list(path: str, args: argparse.Namespace) -> int:
    client: TrustedRouter | None = None
    try:
        client = _client(args)
        result: object
        if path == "regions":
            result = client.regions()
        elif path == "providers":
            result = client.providers()
        elif path == "models":
            result = client.models()
        else:
            return EXIT_USAGE
        if args.json:
            _emit_success(path, result)
        else:
            _print(result)
        return EXIT_SUCCESS
    except (AuthenticationError, PermissionDeniedError) as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_AUTH,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except TrustedRouterError as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_RUNTIME,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return _emit_error(
            args,
            error_type="runtime_error",
            message=str(exc),
            exit_code=EXIT_RUNTIME,
        )
    finally:
        if client is not None:
            with suppress(Exception):
                client.close()


def _cmd_trust(args: argparse.Namespace) -> int:
    try:
        result = fetch_trust_release()
        if args.json:
            _emit_success("trust", result)
        else:
            _print(result)
        return EXIT_SUCCESS
    except (AuthenticationError, PermissionDeniedError) as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_AUTH,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except TrustedRouterError as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_RUNTIME,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return _emit_error(
            args,
            error_type="runtime_error",
            message=str(exc),
            exit_code=EXIT_RUNTIME,
        )


def _cmd_attest(args: argparse.Namespace) -> int:
    client: TrustedRouter | None = None
    session = None
    try:
        client = _client(args)
        if args.session:
            from trustedrouter.attestation import policy_from_trust_release
            from trustedrouter.session import (
                fetch_attestation_again,
                verify_gateway_session,
            )

            policy = policy_from_trust_release()
            session = verify_gateway_session(
                base_url=client.base_url,
                policy=policy,
                connect_ip=args.connect_ip,
            )
            followup = fetch_attestation_again(session)
            session_result = {
                "attestation": session.attestation.as_dict(),
                "followup": followup.as_dict(),
                "exporter": session.exporter.hex(),
            }
            if args.json:
                _emit_success("attest.session", session_result)
            else:
                print("[ok] attestation verified")
                print(f"[ok] TLS cert SHA-256 {session.attestation.cert_sha256}")
                print(f"[ok] image_digest {session.attestation.image_digest}")
                print(f"[ok] TLS exporter bound ({session.exporter.hex()[:16]}...)")
                print("[ok] follow-up /attestation stayed on the attested TLS socket")
                _print(session_result)
            return EXIT_SUCCESS

        doc = client.attestation()
        if not args.verify:
            if args.json:
                _emit_success("attest", {"document": doc.decode("utf-8", errors="replace")})
            else:
                sys.stdout.buffer.write(doc)
            return EXIT_SUCCESS
        # Identity-verification path. TLS exporter and same-socket binding are
        # intentionally reserved for --session, where they can be proven on
        # the exact connection that returned the attestation.
        from trustedrouter.attestation import (
            policy_from_trust_release,
            verify_gateway_attestation,
        )

        policy = policy_from_trust_release()
        verification_result = verify_gateway_attestation(doc, policy=policy)
        if args.json:
            _emit_success("attest.verify", verification_result.as_dict())
        else:
            _print(verification_result.as_dict())
        return EXIT_SUCCESS
    except (AuthenticationError, PermissionDeniedError) as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_AUTH,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except TrustedRouterError as exc:
        return _emit_error(
            args,
            error_type=_sdk_error_type(exc),
            message=str(exc),
            status_code=exc.status_code,
            request_id=exc.request_id,
            exit_code=EXIT_RUNTIME,
            plain_message=f"error: HTTP {exc.status_code}: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return _emit_error(
            args,
            error_type="runtime_error",
            message=str(exc),
            exit_code=EXIT_RUNTIME,
        )
    finally:
        if session is not None:
            with suppress(Exception):
                session.connection.shutdown()
            with suppress(Exception):
                session.connection.close()
        if client is not None:
            with suppress(Exception):
                client.close()


def _add_subcommand_json_option(parser: argparse.ArgumentParser) -> None:
    # Accept both ``trustedrouter --json models`` (canonical global form) and
    # ``trustedrouter models --json`` (the form users naturally try). SUPPRESS
    # prevents the subparser default from overwriting a global True value.
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit deterministic machine-readable JSON.",
    )


def _build_parser(*, json_mode: bool = False) -> argparse.ArgumentParser:
    parser = _CLIArgumentParser(
        prog="trustedrouter",
        description=f"TrustedRouter CLI v{__version__}",
        json_mode=json_mode,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON (JSON Lines when streaming).",
    )
    parser.add_argument(
        "--version",
        action=_VersionAction,
        help="Show the CLI version and exit.",
    )
    parser.add_argument(
        "--retries",
        type=_non_negative_int,
        default=2,
        help="Auto-retry count for 429/5xx (default: 2).",
    )
    sub = parser.add_subparsers(
        dest="cmd",
        required=True,
        parser_class=_CLIArgumentParser,
    )

    chat = sub.add_parser("chat", help="One-shot chat completion.")
    chat.json_mode = json_mode
    _add_subcommand_json_option(chat)
    chat.add_argument(
        "prompt",
        nargs="*",
        help="The user prompt. Pass '-' or omit it when piping stdin.",
    )
    chat.add_argument("-m", "--model", default=AUTO_MODEL,
                      help=f"Model id (default: {AUTO_MODEL}).")
    chat.add_argument("--max-tokens", type=_positive_int, default=200)
    chat.add_argument("--stream", action="store_true",
                      help="Stream tokens to stdout instead of buffering.")
    chat.set_defaults(func=_cmd_chat)

    for name in ("regions", "providers", "models"):
        p = sub.add_parser(name, help=f"List {name}.")
        p.json_mode = json_mode
        _add_subcommand_json_option(p)
        p.set_defaults(func=lambda a, _n=name: _cmd_list(_n, a))

    trust = sub.add_parser("trust", help="Show the published trust release.")
    trust.json_mode = json_mode
    _add_subcommand_json_option(trust)
    trust.set_defaults(func=_cmd_trust)

    att = sub.add_parser("attest", help="Fetch the gateway attestation JWT.")
    att.json_mode = json_mode
    _add_subcommand_json_option(att)
    att.add_argument("--verify", action="store_true",
                     help="Verify signature and workload identity (requires "
                          "`pip install trusted-router-py[attestation]`).")
    att.add_argument("--session", action="store_true",
                     help="Verify the G6 TLS-exporter binding and keep-alive pin.")
    att.add_argument("--connect-ip", default=None,
                     help="Dial this IP while keeping the base-url host as SNI/Host.")
    att.set_defaults(func=_cmd_attest)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    option_terminator = raw_args.index("--") if "--" in raw_args else len(raw_args)
    parser = _build_parser(json_mode="--json" in raw_args[:option_terminator])
    args = parser.parse_args(raw_args)
    if args.cmd == "chat" and not args.model.strip():
        parser.error("--model cannot be empty")
    if args.cmd == "attest" and args.connect_ip is not None:
        if not args.session:
            parser.error("--connect-ip requires --session")
        if not args.connect_ip.strip():
            parser.error("--connect-ip must not be empty")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
