import asyncio

import aiohttp
import pytest

from canmcp.callback import CallbackServer
from canmcp.checks.network import ScanError, validate_url

ISSUER = "https://auth.example.com"


async def test_callback_state_one_use_and_no_code_in_response():
    async with CallbackServer("secret-state", ISSUER, True) as callback:
        async with aiohttp.ClientSession(trust_env=False) as browser:
            async with browser.get(
                callback.redirect_uri, params={"state": "wrong", "code": "stolen"}
            ) as result:
                assert result.status == 400
            assert not callback.future.done()
            params = {"state": "secret-state", "code": "secret-code", "iss": ISSUER}
            async with browser.get(callback.redirect_uri, params=params) as result:
                assert result.status == 200
                assert "secret" not in await result.text()
                assert result.headers["Cache-Control"] == "no-store"
                assert result.headers["Referrer-Policy"] == "no-referrer"
            assert await callback.wait(0.1) == "secret-code"
            async with browser.get(callback.redirect_uri, params=params) as result:
                assert result.status == 410
    # Closed socket; listener was temporary, and outbound loopback policy did not change.
    with pytest.raises(ScanError):
        validate_url(callback.redirect_uri)
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", callback.port)


@pytest.mark.parametrize(
    "params,required,check",
    [
        ({"code": "c"}, True, "oauth.issuer"),
        ({"code": "c", "iss": "https://attacker.example.com"}, False, "oauth.issuer"),
        ({"code": "c", "iss": "https://attacker.example.com"}, True, "oauth.issuer"),
        ({"error": "access_denied", "error_description": "secret-error"}, False, "oauth.denied"),
        ({}, False, "oauth.callback"),
    ],
)
async def test_callback_issuer_and_denial(params, required, check):
    async with CallbackServer("state", ISSUER, required) as callback:
        async with aiohttp.ClientSession(trust_env=False) as browser:
            async with browser.get(
                callback.redirect_uri, params={"state": "state", **params}
            ) as reply:
                assert reply.status == 400
                assert "secret-error" not in await reply.text()
        with pytest.raises(ScanError) as error:
            await callback.wait(0.1)
        assert error.value.check_id == check


@pytest.mark.parametrize(
    "query", ["state=state&state=state&code=c", "state=%FF&code=c", "code=c", "state=other&code=c"]
)
async def test_invalid_callbacks_do_not_consume_attempt(query):
    async with CallbackServer("state", ISSUER, False) as callback:
        async with aiohttp.ClientSession(trust_env=False) as browser:
            async with browser.get(callback.redirect_uri + "?" + query) as reply:
                assert reply.status == 400
                assert not callback.future.done()


async def test_callback_method_host_path_and_timeout():
    async with CallbackServer("state", ISSUER, False) as callback:
        async with aiohttp.ClientSession(trust_env=False) as browser:
            for method, path, headers in [
                ("POST", callback.redirect_uri, {}),
                ("GET", callback.redirect_uri + "/wrong", {}),
                ("GET", callback.redirect_uri, {"Host": "attacker.example.com"}),
            ]:
                async with browser.request(method, path, headers=headers) as reply:
                    assert reply.status == 400
                    assert not callback.future.done()
        with pytest.raises(ScanError, match="Timed out"):
            await callback.wait(0.01)


async def test_callback_cancellation_closes_socket():
    callback = CallbackServer("state", ISSUER, False)

    async def waiting():
        async with callback:
            await callback.wait(60)

    task = asyncio.create_task(waiting())
    while not callback.redirect_uri:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", callback.port)


async def test_callback_parser_error_does_not_log_request_secrets(caplog, capsys):
    async with CallbackServer("state", ISSUER, False) as callback:
        reader, writer = await asyncio.open_connection("127.0.0.1", callback.port)
        try:
            writer.write(
                b"GET /oauth/callback?code=secret-code HTTP/1.1\r\nBroken secret-header\r\n\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 1)
            assert response.startswith(b"HTTP/1.0 400") or response.startswith(b"HTTP/1.1 400")
        finally:
            writer.close()
            await writer.wait_closed()
        assert not callback.future.done()
    captured = capsys.readouterr()
    assert "secret" not in caplog.text + captured.out + captured.err
