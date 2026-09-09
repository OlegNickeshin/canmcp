import argparse
import asyncio
import json
import math

from canmcp import __version__
from canmcp.models import Status
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
        help="Per-request timeout (default 10, maximum 30); scan budget is 60 seconds",
    )
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(scan(args.url, timeout=args.timeout))
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
