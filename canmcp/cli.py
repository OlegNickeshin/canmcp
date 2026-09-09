import argparse
import asyncio
import json
import math
import os
import re

from canmcp import __version__
from canmcp.checks.network import ScanError
from canmcp.models import Status
from canmcp.oauth import OAuthOptions
from canmcp.scanner import scan


def request_timeout(value):
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(seconds) or not 0 < seconds <= 30:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 30 seconds")
    return seconds


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="canmcp", description="Local remote MCP compatibility checks; never executes tools."
    )
    parser.add_argument("--version", action="version", version=f"canmcp {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Check a public remote MCP endpoint")
    check.add_argument("url")
    check.add_argument("--json", action="store_true", help="Print only the JSON report")
    check.add_argument(
        "--timeout",
        type=request_timeout,
        default=10,
        metavar="SECONDS",
        help="Per-request timeout (default 10, maximum 30); each MCP phase has 60 seconds",
    )
    check.add_argument(
        "--oauth",
        action="store_true",
        help="Sign in interactively when protected; may register an OAuth client",
    )
    check.add_argument("--client-id", help="Use a pre-registered OAuth client (requires --issuer)")
    check.add_argument("--issuer", help="Pin the exact advertised authorization server issuer")
    check.add_argument(
        "--client-secret-env",
        metavar="NAME",
        help="Read a pre-registered client secret only from this named environment variable",
    )
    check.add_argument(
        "--token-auth-method", choices=["none", "client_secret_basic", "client_secret_post"]
    )
    check.add_argument(
        "--scope",
        action="append",
        metavar="SCOPE",
        help="Request this scope instead of discovery defaults; repeat for multiple scopes",
    )
    check.add_argument("--callback-port", type=int, help="Local callback port (default: ephemeral)")
    check.add_argument(
        "--oauth-timeout",
        type=float,
        metavar="SECONDS",
        help="Browser authorization wait (default 180, maximum 600 seconds)",
    )
    args = parser.parse_args(argv)
    oauth = None
    oauth_parameters = (
        args.client_id,
        args.issuer,
        args.client_secret_env,
        args.token_auth_method,
        args.scope,
        args.callback_port,
        args.oauth_timeout,
    )
    if not args.oauth and any(value is not None for value in oauth_parameters):
        parser.error("OAuth options require --oauth")
    if args.oauth:
        secret = None
        if args.client_secret_env is not None:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.client_secret_env):
                parser.error("Invalid environment variable name for the client secret")
            secret = os.environ.get(args.client_secret_env)
            if not secret:
                parser.error("The named client-secret environment variable is empty or unset")
        oauth = OAuthOptions(
            client_id=args.client_id,
            issuer=args.issuer,
            client_secret=secret,
            token_auth_method=args.token_auth_method
            or ("client_secret_basic" if secret else "none"),
            scopes=args.scope,
            callback_port=args.callback_port if args.callback_port is not None else 0,
            wait_timeout=args.oauth_timeout if args.oauth_timeout is not None else 180,
        )
        try:
            oauth.validate()
        except ScanError as exc:
            parser.error(str(exc))
    try:
        kwargs = {"oauth": oauth} if oauth is not None else {}
        report = asyncio.run(scan(args.url, timeout=args.timeout, **kwargs))
    except KeyboardInterrupt:
        return 130
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=True))
    else:
        print(f"URL: {report.url}")
        if report.final_url and report.final_url != report.url:
            print(f"Final URL: {report.final_url}")
        if report.protocol_version:
            print(f"MCP revision: {report.protocol_version}")
        print(f"\nGeneric MCP: {report.generic.status.upper()}")
        for item in report.generic.checks:
            print(f"- {item.status.upper()} [{item.id}] {item.message}")
        for key, title in (("chatgpt", "ChatGPT"), ("claude", "Claude")):
            profile = report.clients[key]
            print(f"\n{title}: {profile.status.upper()}")
            for reason in profile.reasons:
                print(f"- {reason.message}")
        print(
            "\nLocal diagnostic only; cloud access, account policies, "
            "and tool execution are unverified."
        )
    statuses = [report.generic.status, *(p.status for p in report.clients.values())]
    if Status.FAIL in statuses:
        return 1
    return 2 if Status.WARN in statuses else 0
