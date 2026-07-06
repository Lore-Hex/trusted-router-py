"""TrustedRouter CLI — sniff-tests for the gateway.

Usage:
  trustedrouter chat "hello"          # one-shot completion (uses AUTO_MODEL)
  trustedrouter chat -m claude "hi"   # specify model
  trustedrouter regions               # list deployed regions
  trustedrouter providers             # list provider catalog
  trustedrouter models                # list model catalog
  trustedrouter attest                # fetch raw attestation JWT
  trustedrouter attest --verify       # fetch + verify against trust release
  trustedrouter trust                 # show the published trust release

Reads bearer from $TRUSTEDROUTER_API_KEY (or $TR_API_KEY). Writes
nothing but JSON or text to stdout — composable with `jq`."""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
from contextlib import suppress

from trustedrouter import (
    AUTO_MODEL,
    AsyncTrustedRouter,
    AuthenticationError,
    TrustedRouter,
    TrustedRouterError,
    __version__,
    fetch_trust_release,
)


def _bearer() -> str | None:
    return (
        os.environ.get("TRUSTEDROUTER_API_KEY")
        or os.environ.get("TR_API_KEY")
        or None
    )


def _client(args: argparse.Namespace) -> TrustedRouter:
    return TrustedRouter(
        api_key=_bearer(),
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


def _cmd_chat(args: argparse.Namespace) -> int:
    client = _client(args)
    try:
        prompt = " ".join(args.prompt)
        if not prompt:
            print("error: empty prompt", file=sys.stderr)
            return 2
        if args.stream:
            for tok in client.chat_completions_stream(
                model=args.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=args.max_tokens,
            ):
                print(tok, end="", flush=True)
            print()
            return 0
        resp = client.chat_completions(
            model=args.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=args.max_tokens,
        )
        print(resp.choices[0].message.content or "")
        return 0
    except AuthenticationError as exc:
        print(f"error: {exc} (set TRUSTEDROUTER_API_KEY)", file=sys.stderr)
        return 3
    except TrustedRouterError as exc:
        print(f"error: HTTP {exc.status_code}: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


def _cmd_list(path: str, args: argparse.Namespace) -> int:
    client = _client(args)
    try:
        if path == "regions":
            _print(client.regions())
        elif path == "providers":
            _print(client.providers())
        elif path == "models":
            _print(client.models())
        else:
            return 2
        return 0
    except TrustedRouterError as exc:
        print(f"error: HTTP {exc.status_code}: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


def _cmd_trust(_args: argparse.Namespace) -> int:
    try:
        _print(fetch_trust_release())
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _cmd_attest(args: argparse.Namespace) -> int:
    client = _client(args)
    session = None
    try:
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
            print("[ok] attestation verified")
            print(f"[ok] TLS cert SHA-256 {session.attestation.cert_sha256}")
            print(f"[ok] image_digest {session.attestation.image_digest}")
            print(f"[ok] TLS exporter bound ({session.exporter.hex()[:16]}...)")
            followup = fetch_attestation_again(session)
            print("[ok] follow-up /attestation stayed on the attested TLS socket")
            _print(
                {
                    "attestation": session.attestation.as_dict(),
                    "followup": followup.as_dict(),
                    "exporter": session.exporter.hex(),
                }
            )
            return 0

        doc = client.attestation()
        if not args.verify:
            sys.stdout.buffer.write(doc)
            return 0
        # Verified path — fetch the live cert from the same host so we
        # can bind it, then run the full verification.
        from trustedrouter.attestation import (
            policy_from_trust_release,
            verify_gateway_attestation,
        )

        host = client.base_url.split("//", 1)[-1].split("/", 1)[0]
        port = 443
        if ":" in host:
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)
        ctx = ssl.create_default_context()
        raw_sock = socket.create_connection((host, port), timeout=10.0)
        with ctx.wrap_socket(
            raw_sock,
            server_hostname=host,
        ) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
        policy = policy_from_trust_release()
        result = verify_gateway_attestation(
            doc, policy=policy, tls_cert_der=cert_der
        )
        _print(result.as_dict())
        return 0
    except TrustedRouterError as exc:
        print(f"error: HTTP {exc.status_code}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            with suppress(Exception):
                session.connection.shutdown()
            with suppress(Exception):
                session.connection.close()
        client.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustedrouter",
        description=f"TrustedRouter CLI v{__version__}",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Auto-retry count for 429/5xx (default: 2).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    chat = sub.add_parser("chat", help="One-shot chat completion.")
    chat.add_argument("prompt", nargs="+", help="The user prompt.")
    chat.add_argument("-m", "--model", default=AUTO_MODEL,
                      help=f"Model id (default: {AUTO_MODEL}).")
    chat.add_argument("--max-tokens", type=int, default=200)
    chat.add_argument("--stream", action="store_true",
                      help="Stream tokens to stdout instead of buffering.")
    chat.set_defaults(func=_cmd_chat)

    for name in ("regions", "providers", "models"):
        p = sub.add_parser(name, help=f"List {name}.")
        p.set_defaults(func=lambda a, _n=name: _cmd_list(_n, a))

    trust = sub.add_parser("trust", help="Show the published trust release.")
    trust.set_defaults(func=_cmd_trust)

    att = sub.add_parser("attest", help="Fetch the gateway attestation JWT.")
    att.add_argument("--verify", action="store_true",
                     help="Verify against the trust release (requires "
                          "`pip install trusted-router-py[attestation]`).")
    att.add_argument("--session", action="store_true",
                     help="Verify the G6 TLS-exporter binding and keep-alive pin.")
    att.add_argument("--connect-ip", default=None,
                     help="Dial this IP while keeping the base-url host as SNI/Host.")
    att.set_defaults(func=_cmd_attest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())


# Delete the unused AsyncTrustedRouter import — keep flake clean.
_ = AsyncTrustedRouter
