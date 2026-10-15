# tests/secrets/test_vault_agent.py
from __future__ import annotations

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.secrets import SecretNotFound  # noqa: E402
from secops_ingest.secrets.vault_agent import VaultAgentSecretProvider  # noqa: E402


def _provider(handler, **kwargs):
    return VaultAgentSecretProvider(
        socket="/run/vault-agent/agent.sock",
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def test_sends_no_token_header():
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"data": {"data": {"api_key": "abc123xyz"}}})

    provider = _provider(handler)
    assert provider.fetch_locator({"path": "secops/xdr_ro", "field": "api_key"}) == "abc123xyz"
    assert "x-vault-token" not in {k.lower() for k in seen["headers"]}  # type: ignore[union-attr]
    assert "/v1/secret/data/secops/xdr_ro" in str(seen["url"])


def test_a_missing_field_is_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"data": {"other": "x"}}})

    with pytest.raises(SecretNotFound):
        _provider(handler).fetch_locator({"path": "p", "field": "api_key"})


def test_a_404_is_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": []})

    with pytest.raises(SecretNotFound):
        _provider(handler).fetch_locator({"path": "p", "field": "f"})


def test_a_403_is_an_error_naming_neither_path_nor_value():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": ["permission denied"]})

    with pytest.raises(Exception) as exc:
        _provider(handler).fetch_locator({"path": "secops/private", "field": "f"})
    assert "secops/private" not in str(exc.value)
    assert "403" in str(exc.value)


def test_whole_secret_without_a_field_uses_the_value_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"data": {"value": "whole-secret"}}})

    assert _provider(handler).fetch_locator({"path": "p"}) == "whole-secret"


def test_prefix_is_applied():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"data": {"data": {"f": "v"}}})

    _provider(handler, prefix="metabase/").fetch_locator({"path": "warehouse", "field": "f"})
    assert "/v1/secret/data/metabase/warehouse" in seen["url"]


def test_lease_returns_the_whole_data_block():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith("/v1/database/creds/ingest")
        return httpx.Response(200, json={"data": {"username": "v-cert-x", "password": "pw"}})

    got = _provider(handler).lease("database/creds/ingest")
    assert got == {"username": "v-cert-x", "password": "pw"}


def test_a_locator_without_a_path_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not call the backend")

    with pytest.raises(Exception, match="requires a 'path'"):
        _provider(handler).fetch_locator({"field": "f"})
