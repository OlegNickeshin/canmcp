from canmcp.models import Check, Evidence, Generic, Status, worst


def evaluate(evidence: Evidence) -> Generic:
    checks = list(evidence.checks)
    if not evidence.protocol_ok and not any(c.status != Status.PASS for c in checks):
        checks.append(Check("coverage", Status.WARN, "MCP protocol inspection did not complete."))
    return Generic(worst(checks), checks)


def base_reasons(generic: Generic) -> list[Check]:
    reasons = [check for check in generic.checks if check.status != Status.PASS]
    if not reasons:
        reasons.append(Check("mcp", Status.PASS, "All implemented MCP protocol checks passed."))
    return reasons
