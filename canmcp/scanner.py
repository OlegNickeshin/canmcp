import asyncio

from canmcp.checks.network import SafeHTTP, ScanError, display_url, validate_url
from canmcp.checks.protocol import check_protocol
from canmcp.compat import chatgpt, claude, generic
from canmcp.models import Evidence, Report, Status


async def scan(url: str, *, timeout: float = 10, http=None) -> Report:
    evidence = Evidence(url)
    try:
        evidence.url = str(validate_url(url))
        evidence.add(
            "url", Status.PASS, "Absolute HTTP(S) URL accepted by the public-target policy."
        )
        async with asyncio.timeout(60):
            if http is None:
                async with SafeHTTP(timeout) as transport:
                    await check_protocol(transport, evidence)
            else:
                await check_protocol(http, evidence)
    except ScanError as exc:
        status = Status.WARN if exc.check_id in {"limits", "unsupported_version"} else Status.FAIL
        evidence.add(exc.check_id, status, str(exc))
    except TimeoutError:
        evidence.add(
            "limits", Status.WARN, "60-second scan budget exhausted; inspection is incomplete."
        )
    baseline = generic.evaluate(evidence)
    return Report(
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
