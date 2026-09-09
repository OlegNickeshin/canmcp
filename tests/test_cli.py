import json

import pytest

from canmcp.cli import main
from canmcp.models import Check, Generic, Profile, Report, Status
from canmcp.oauth import present_login


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


@pytest.mark.parametrize(
    "arguments",
    [
        ["--client-id", "id"],
        ["--oauth", "--client-id", "id"],
        ["--oauth", "--callback-port", "65536"],
        ["--oauth", "--oauth-timeout", "NaN"],
        ["--oauth", "--oauth-timeout", "601"],
        ["--oauth", "--scope", "invalid scope"],
        ["--oauth", "--token-auth-method", "client_secret_basic"],
        ["--oauth", "--client-secret-env", "INVALID-NAME"],
    ],
)
def test_oauth_invalid_cli_arguments_never_scan(monkeypatch, arguments):
    def unexpected_scan(*args, **kwargs):
        pytest.fail("Invalid OAuth options must not perform discovery or send credentials")

    monkeypatch.setattr("canmcp.cli.scan", unexpected_scan)
    with pytest.raises(SystemExit) as error:
        main(["check", "https://example.com/mcp", *arguments])
    assert error.value.code == 2


def test_oauth_json_stdout_and_named_environment_secret(monkeypatch, capsys):
    monkeypatch.setenv("CANMCP_TEST_SECRET", "secret-never-printed")

    async def scan(url, *, timeout, oauth):
        assert oauth.client_id == "existing-client"
        assert oauth.issuer == "https://issuer.example.com"
        assert oauth.client_secret == "secret-never-printed"
        assert oauth.token_auth_method == "client_secret_basic"
        assert oauth.scopes == ["tools.read", "metadata.read"]
        assert oauth.callback_port == 8765
        assert oauth.wait_timeout == 60
        assert "secret-never-printed" not in repr(oauth)
        await present_login("https://issuer.example.com/authorize?state=public-login-state")
        checks = [Check("oauth.authenticated_mcp", Status.PASS, "Protected inspection completed")]
        return Report(
            url,
            Generic(Status.PASS, checks),
            {name: Profile(Status.PASS, checks) for name in ("chatgpt", "claude")},
        )

    monkeypatch.setattr("canmcp.cli.scan", scan)
    assert (
        main(
            [
                "check",
                "https://example.com/mcp",
                "--oauth",
                "--json",
                "--client-id",
                "existing-client",
                "--issuer",
                "https://issuer.example.com",
                "--client-secret-env",
                "CANMCP_TEST_SECRET",
                "--scope",
                "tools.read",
                "--scope",
                "metadata.read",
                "--callback-port",
                "8765",
                "--oauth-timeout",
                "60",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["generic"]["status"] == "pass"
    assert "public-login-state" in captured.err and "public-login-state" not in captured.out
    assert "secret-never-printed" not in captured.out + captured.err


def test_missing_named_secret_is_configuration_error(monkeypatch, capsys):
    monkeypatch.delenv("CANMCP_TEST_SECRET", raising=False)
    with pytest.raises(SystemExit) as error:
        main(
            [
                "check",
                "https://example.com/mcp",
                "--oauth",
                "--client-secret-env",
                "CANMCP_TEST_SECRET",
            ]
        )
    assert error.value.code == 2
    assert "empty or unset" in capsys.readouterr().err
