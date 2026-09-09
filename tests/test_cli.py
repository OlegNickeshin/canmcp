import json

import pytest

from canmcp.cli import main
from canmcp.models import Check, Generic, Profile, Report, Status


def test_json_rejects_ssrf_without_network(capsys):
    assert main(["check", "http://127.0.0.1/mcp", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["generic"]["status"] == "fail"
    assert report["generic"]["checks"][0]["id"] == "ssrf"
    assert report["clients"]["chatgpt"]["reasons"]


def test_query_redaction(capsys):
    main(["check", "http://127.0.0.1/mcp?token=secret", "--json"])
    assert "secret" not in capsys.readouterr().out


@pytest.mark.parametrize("status,code", [(Status.PASS, 0), (Status.FAIL, 1), (Status.WARN, 2)])
def test_output_and_exit_codes(monkeypatch, capsys, status, code):
    async def scan(*args, **kwargs):
        checks = [Check("test", status, "Explanation")]
        return Report(
            "https://example.com/mcp",
            Generic(status, checks),
            {name: Profile(status, checks) for name in ("chatgpt", "claude")},
        )

    monkeypatch.setattr("canmcp.cli.scan", scan)
    assert main(["check", "https://example.com/mcp"]) == code
    output = capsys.readouterr().out
    assert f"Generic MCP: {status.upper()}" in output
    assert f"ChatGPT: {status.upper()}" in output
    assert f"Claude: {status.upper()}" in output
    assert "Explanation" in output


@pytest.mark.parametrize("value", ["0", "-1", "NaN", "inf", "31"])
def test_invalid_timeout(value):
    with pytest.raises(SystemExit) as error:
        main(["check", "https://example.com", "--timeout", value])
    assert error.value.code == 2
