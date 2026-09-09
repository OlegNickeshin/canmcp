import pytest

from canmcp.checks.network import ScanError
from canmcp.checks.oauth import bearer_challenge, metadata_urls
from canmcp.scanner import scan
from tests.conftest import URL, response

AS = "https://auth.example.com/.well-known/oauth-authorization-server/tenant"


async def test_oauth_metadata(oauth):
    report = await scan(URL, http=oauth)
    assert report.generic.status == "warn"  # protected protocol has not been exercised
    ids = {c.id: c.status for c in report.generic.checks}
    for id in ["oauth.protected_resource", "oauth.authorization_server", "oauth.pkce", "oauth.dcr"]:
        assert ids[id] == "pass"
    assert all(call[0] == "GET" for call in oauth.calls[1:])
    assert all(not call[1].endswith(("/token", "/register", "/authorize")) for call in oauth.calls)
    assert report.protocol_version is None


@pytest.mark.parametrize(
    "field,value,check",
    [
        ("issuer", "https://wrong.example.com", "oauth.issuer"),
        ("code_challenge_methods_supported", ["plain"], "oauth.pkce"),
        ("response_types_supported", ["token"], "oauth.authorization_code"),
        ("token_endpoint", "http://auth.example.com/token", "oauth.metadata"),
        ("token_endpoint", "https://127.0.0.1/token", "ssrf"),
        ("client_id_metadata_document_supported", "true", "oauth.metadata"),
    ],
)
async def test_invalid_oauth(oauth, field, value, check):
    oauth.discovery[AS][field] = value
    report = await scan(URL, http=oauth)
    assert report.generic.status == "fail"
    assert any(c.id == check and c.status == "fail" for c in report.generic.checks)


async def test_dcr_optional_cimd_client_difference(oauth):
    metadata = oauth.discovery[AS]
    del metadata["registration_endpoint"]
    metadata["client_id_metadata_document_supported"] = True
    metadata["token_endpoint_auth_methods_supported"] = ["private_key_jwt"]
    report = await scan(URL, http=oauth)
    assert not any(c.id == "chatgpt.registration" for c in report.clients["chatgpt"].reasons)
    assert any(c.id == "claude.registration" for c in report.clients["claude"].reasons)
    assert next(c for c in report.generic.checks if c.id == "oauth.dcr").status == "pass"


async def test_resource_mismatch(oauth):
    oauth.discovery["https://mcp.example.com/metadata"]["resource"] = (
        "https://other.example.com/mcp"
    )
    assert (await scan(URL, http=oauth)).generic.status == "fail"


async def test_prm_and_oidc_fallback(oauth):
    oauth.override = lambda method, url, payload: (
        response(status=401, url=url, headers={"www-authenticate": "Bearer realm=example"})
        if method == "POST"
        else None
    )
    resource = oauth.discovery.pop("https://mcp.example.com/metadata")
    oauth.discovery["https://mcp.example.com/.well-known/oauth-protected-resource"] = resource
    metadata = oauth.discovery.pop(AS)
    oauth.discovery["https://auth.example.com/tenant/.well-known/openid-configuration"] = metadata
    report = await scan(URL, http=oauth)
    assert report.generic.status == "warn"
    assert any(
        c.id == "oauth.authorization_server" and c.status == "pass" for c in report.generic.checks
    )


async def test_malicious_metadata_url(oauth):
    oauth.override = lambda method, url, payload: response(
        status=401,
        url=url,
        headers={
            "www-authenticate": 'Bearer resource_metadata="http://169.254.169.254/latest/meta-data/"'
        },
    )
    report = await scan(URL, http=oauth)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "ssrf"
    assert len(oauth.calls) == 1


@pytest.mark.parametrize(
    "header",
    [
        "",
        'Basic realm="Bearer resource_metadata=oops"',
        'Bearer resource_metadata="unterminated',
        'Bearer scope="a", scope="b"',
        'Bearer realm="a", Bearer realm="b"',
    ],
)
def test_bad_www_authenticate(header):
    with pytest.raises(ScanError):
        bearer_challenge(header)


def test_multiple_challenges_and_quoted_commas():
    result = bearer_challenge(
        'Basic realm="a,b", Bearer scope="read write", '
        'resource_metadata="https://a.example/meta", Digest realm="c"'
    )
    assert result == {"scope": "read write", "resource_metadata": "https://a.example/meta"}


def test_discovery_paths():
    assert metadata_urls("https://auth.example.com/tenant")[0].endswith(
        "oauth-authorization-server/tenant"
    )
    assert len(metadata_urls("https://auth.example.com")) == 2


async def test_invalid_first_issuer_valid_second(oauth):
    oauth.discovery["https://mcp.example.com/metadata"]["authorization_servers"].insert(
        0, "https://bad.example.com"
    )
    report = await scan(URL, http=oauth)
    assert report.generic.status == "warn"
    assert any(c.id == "oauth.alternatives" for c in report.generic.checks)
