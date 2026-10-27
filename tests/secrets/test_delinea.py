# tests/secrets/test_delinea.py
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.secrets import Secret, SecretNotFound  # noqa: E402
from secops_ingest.secrets.delinea_client import SecretServerClient  # noqa: E402

TOKEN_PATH = "/oauth2/token"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _client(handler, clock=None, run_id="run-42"):
    return SecretServerClient(
        base_url="https://pam.example.com",
        client_id="sdk-client-9",
        client_secret=Secret("bootstrap-secret-value"),
        run_id=run_id,
        transport=httpx.MockTransport(handler),
        clock=clock or Clock(),
    )


def test_fetches_one_field_with_the_three_mandatory_parameters():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(200, json={"itemValue": "the-password"})

    assert _client(handler).field("4821", "password") == "the-password"

    fetch = seen[-1]
    assert fetch.url.path == "/api/v1/secrets/4821/fields/password"
    query = parse_qs(urlparse(str(fetch.url)).query)
    # noAutoCheckout: a plain GET on a checkout-enabled secret can check it
    # out to this account and trigger rotation on check-in.
    assert query["noAutoCheckout"] == ["true"]
    # autoComment lands in Secret Server's own access audit record.
    assert query["autoComment"] == ["run-42"]
    assert fetch.headers["authorization"] == "Bearer tok"


def test_the_token_is_requested_once_and_reused():
    calls = {"token": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(200, json={"itemValue": "v"})

    client = _client(handler)
    client.field("1", "password")
    client.field("2", "password")
    assert calls["token"] == 1


def test_drift_is_subtracted_so_an_expiring_token_is_replaced_early():
    # python-tss-sdk ADDS its drift (server.py:272-278) and so presents an
    # expired token for up to five minutes. This asserts the opposite sign.
    issued: list[str] = []
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            issued.append(f"tok{len(issued)}")
            return httpx.Response(200, json={"access_token": issued[-1], "expires_in": 600})
        return httpx.Response(200, json={"itemValue": "v"})

    client = _client(handler, clock=clock)
    client.field("1", "password")
    assert issued == ["tok0"]

    # 310s in: still inside 600s, but inside the 300s safety margin too.
    clock.now += 310
    client.field("2", "password")
    assert issued == ["tok0", "tok1"]


def test_a_401_refreshes_once_and_retries():
    state = {"tokens": 0, "fetches": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            state["tokens"] += 1
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        state["fetches"] += 1
        if state["fetches"] == 1:
            return httpx.Response(401, json={"message": "unauthorized"})
        return httpx.Response(200, json={"itemValue": "after-retry"})

    assert _client(handler).field("1", "password") == "after-retry"
    assert state["tokens"] == 2
    assert state["fetches"] == 2


def test_a_second_401_is_not_retried_again():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(401, json={"message": "unauthorized"})

    with pytest.raises(Exception, match="401"):
        _client(handler).field("1", "password")


def test_a_404_is_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(404, json={"message": "not found"})

    with pytest.raises(SecretNotFound):
        _client(handler).field("1", "password")


def test_error_text_never_contains_the_bootstrap_secret_or_the_value():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(
                400, json={"error": "invalid_client bootstrap-secret-value"}
            )
        return httpx.Response(200, json={"itemValue": "v"})  # pragma: no cover

    with pytest.raises(Exception) as exc:
        _client(handler).field("1", "password")
    assert "bootstrap-secret-value" not in str(exc.value)


def test_a_non_numeric_secret_id_is_rejected_before_any_request():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not reach the backend")

    with pytest.raises(Exception, match="numeric secret id"):
        _client(handler).field("../../admin", "password")


from secops_ingest.secrets.delinea import DelineaSecretProvider  # noqa: E402


def test_provider_resolves_a_locator():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert request.url.path == "/api/v1/secrets/4821/fields/password"
        return httpx.Response(200, json={"itemValue": "resolved"})

    provider = DelineaSecretProvider(
        base_url="https://pam.example.com",
        client_id="sdk-client-9",
        credential=Secret("bootstrap-secret-value"),
        run_id="run-7",
        transport=httpx.MockTransport(handler),
    )
    assert provider.fetch_locator({"secret": "4821", "field": "password"}) == "resolved"


def test_provider_requires_a_credential():
    with pytest.raises(Exception, match="credential"):
        DelineaSecretProvider(base_url="https://pam.example.com", client_id="sdk-client-9")


def test_provider_rejects_a_locator_without_a_secret_id():
    provider = DelineaSecretProvider(
        base_url="https://pam.example.com",
        client_id="sdk-client-9",
        credential=Secret("bootstrap-secret-value"),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})),
    )
    with pytest.raises(Exception, match="requires a 'secret'"):
        provider.fetch_locator({"field": "password"})


@pytest.mark.parametrize(
    "url", ["http://pam.example.com", "pam.example.com", "ftp://pam.example.com", ""]
)
def test_a_non_https_base_url_is_rejected_before_any_request(url):
    from secops_ingest.secrets import SecretError

    def handler(request):  # pragma: no cover - must never be reached
        raise AssertionError("no request may be made")

    with pytest.raises(SecretError, match="must use https://"):
        SecretServerClient(
            base_url=url,
            client_id="c",
            client_secret=Secret("s"),
            transport=httpx.MockTransport(handler),
        )


def test_an_https_base_url_is_accepted_in_any_case():
    client = SecretServerClient(
        base_url="HTTPS://pam.example.com/",
        client_id="c",
        client_secret=Secret("s"),
        transport=httpx.MockTransport(lambda r: httpx.Response(200)),
    )
    client.close()


# -- bodies that are not what Secret Server sends ---------------------------------


def _token_then(field_response):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return field_response

    return handler


def test_a_non_json_field_body_is_a_secret_error():
    # A captive proxy or WAF answering 200 with a page.
    from secops_ingest.secrets import SecretError

    page = httpx.Response(200, text="<html>Sign in to continue</html>")
    with pytest.raises(SecretError, match="non-JSON body reading secret 4821"):
        _client(_token_then(page)).field("4821", "password")


def test_a_non_json_token_body_is_a_secret_error():
    from secops_ingest.secrets import SecretError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>proxy</html>")

    with pytest.raises(SecretError, match="non-JSON body during authentication"):
        _client(handler).field("4821", "password")


@pytest.mark.parametrize("body", [b'{"itemValue": null}', b'{"itemValue": ""}', b"null"])
def test_an_empty_field_is_refused_rather_than_sent_as_none(body):
    # str(None) is "None", which used to reach the vendor as the password.
    from secops_ingest.secrets import SecretError

    response = httpx.Response(200, content=body, headers={"content-type": "application/json"})
    with pytest.raises(SecretError, match="field password is empty"):
        _client(_token_then(response)).field("4821", "password")
