import asyncio

from canmcp.checks.network import SafeHTTP, ScanError, display_url, validate_url
from canmcp.checks.protocol import check_protocol
from canmcp.compat import chatgpt, claude, generic
from canmcp.models import Evidence, Report, Status
from canmcp.oauth import OAuthOptions, authorize, present_login


async def inspect(http, evidence, oauth, present):
    async with asyncio.timeout(60):
        await check_protocol(http, evidence, issuer=oauth.issuer if oauth else None)
    if oauth is None:
        return
    if not evidence.protected:
        evidence.add(
            "oauth.authentication",
            Status.PASS,
            "No protected operation encountered; interactive OAuth was not started.",
        )
        return
    if any(check.status == Status.FAIL for check in evidence.checks):
        return  # Never send credentials after failed discovery or binding checks.
    async with asyncio.timeout(oauth.wait_timeout + 60):
        credential = await authorize(http, evidence, oauth, present=present)
    authorized = Evidence(evidence.final_url)
    try:
        async with asyncio.timeout(60):
            await check_protocol(http, authorized, credential=credential)
    finally:
        credential.value = ""
        evidence.checks.extend(authorized.checks)
        evidence.protocol_version = authorized.protocol_version
        evidence.advertised_versions = authorized.advertised_versions
        evidence.protocol_ok = authorized.protocol_ok
        evidence.tool_count = authorized.tool_count
        evidence.missing_descriptions = authorized.missing_descriptions
        evidence.missing_annotations = authorized.missing_annotations
        evidence.missing_claude_hints = authorized.missing_claude_hints
    if authorized.protocol_ok:
        evidence.checks = [check for check in evidence.checks if check.id != "oauth.authentication"]
        evidence.add(
            "oauth.authenticated_mcp",
            Status.PASS,
            "Protected MCP inspection completed after interactive OAuth authorization.",
        )


async def scan(
    url: str,
    *,
    timeout: float = 10,
    http=None,
    oauth: OAuthOptions | None = None,
    present=present_login,
) -> Report:
    evidence = Evidence(url)
    try:
        evidence.url = str(validate_url(url))
        evidence.add(
            "url", Status.PASS, "Absolute HTTP(S) URL accepted by the public-target policy."
        )
        if oauth is not None:
            oauth.validate()
            if not evidence.url.startswith("https://"):
                raise ScanError("oauth.https", "Interactive OAuth requires an HTTPS MCP endpoint.")
        if http is None:
            async with SafeHTTP(timeout) as transport:
                await inspect(transport, evidence, oauth, present)
        else:
            await inspect(http, evidence, oauth, present)
    except ScanError as exc:
        status = (
            Status.WARN
            if exc.check_id
            in {
                "limits",
                "unsupported_version",
                "oauth.client_setup",
                "oauth.denied",
                "oauth.timeout",
            }
            else Status.FAIL
        )
        evidence.add(exc.check_id, status, str(exc))
    except TimeoutError:
        evidence.add(
            "limits", Status.WARN, "Scan phase time budget exhausted; inspection is incomplete."
        )
    baseline = generic.evaluate(evidence)
    report = Report(
        url=display_url(url),
        generic=baseline,
        clients={
            "chatgpt": chatgpt.evaluate(evidence, baseline),
            "claude": claude.evaluate(evidence, baseline),
        },
        protocol_version=evidence.protocol_version,
        advertised_versions=evidence.advertised_versions,
        final_url=display_url(evidence.final_url) if evidence.final_url else None,
    )
    if oauth is not None:
        report.limitations.append(
            "OAuth uses CanMCP's client; ChatGPT/Claude authorization was not exercised."
        )
    return report
