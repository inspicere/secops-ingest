"""Offline tests for shared Cortex auth and configuration.

No network and no Vault: the secret provider is replaced with a stub, so the
header set and the base-URL assembly are asserted directly.
"""

from __future__ import annotations

import pytest

from secops_ingest.sources import _cortex


class StubProvider:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.asked: list[str] = []

    def get(self, name: str) -> str:
        self.asked.append(name)
        return self.values[name]


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubProvider:
    p = StubProvider({
        "xdr.api_key": "k" * 128,
        "xdr.api_key_id": "42",
        "xdr.url": "https://api-tenant.example.com",
    })
    monkeypatch.setattr(_cortex, "get_provider", lambda: p)
    return p


def test_resolve_reads_the_three_fields_of_one_secret(stub: StubProvider) -> None:
    creds = _cortex.resolve("xdr", "/public_api/v1")
    assert stub.asked == ["xdr.api_key", "xdr.api_key_id", "xdr.url"]
    assert creds.key_id == "42"
    assert creds.base == "https://api-tenant.example.com/public_api/v1"


def test_resolve_adds_the_api_prefix_when_the_stored_host_lacks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = StubProvider({"x.api_key": "k", "x.api_key_id": "1",
                      "x.url": "https://tenant.example.com"})
    monkeypatch.setattr(_cortex, "get_provider", lambda: p)
    assert _cortex.resolve("x", "/public_api/v1").base == (
        "https://api-tenant.example.com/public_api/v1")


def test_resolve_does_not_double_the_api_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    p = StubProvider({"x.api_key": "k", "x.api_key_id": "1",
                      "x.url": "https://api-tenant.example.com"})
    monkeypatch.setattr(_cortex, "get_provider", lambda: p)
    assert _cortex.resolve("x", "/p").base == "https://api-tenant.example.com/p"


def test_resolve_strips_a_trailing_slash_before_appending_the_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = StubProvider({"x.api_key": "k", "x.api_key_id": "1",
                      "x.url": "https://api-tenant.example.com/"})
    monkeypatch.setattr(_cortex, "get_provider", lambda: p)
    assert _cortex.resolve("x", "/p").base == "https://api-tenant.example.com/p"


def test_headers_are_standard_auth_with_the_key_id(stub: StubProvider) -> None:
    """x-xdr-auth-id is required for STANDARD keys, not only Advanced ones.

    Measured 2026-09-14: every request without it returned 401 on both tenants.
    """
    h = _cortex.headers(_cortex.resolve("xdr", "/p"))
    assert h["Authorization"] == "k" * 128
    assert h["x-xdr-auth-id"] == "42"
    assert h["Content-Type"] == "application/json"


def test_headers_carry_no_advanced_signature_fields(stub: StubProvider) -> None:
    """Advanced headers 401 on these tenants; sending them would be a regression."""
    h = _cortex.headers(_cortex.resolve("xdr", "/p"))
    assert "x-xdr-nonce" not in h
    assert "x-xdr-timestamp" not in h


def test_resolve_registers_the_key_for_redaction(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(_cortex, "register_secret", seen.append)
    _cortex.resolve("xdr", "/p")
    assert "k" * 128 in seen


def test_env_int_rejects_a_non_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_T", "abc")
    with pytest.raises(ValueError):
        _cortex.env_int("SECOPS_T", 10)


def test_env_int_rejects_zero_and_negatives(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_T", "0")
    with pytest.raises(ValueError):
        _cortex.env_int("SECOPS_T", 10)


def test_env_int_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_T", raising=False)
    assert _cortex.env_int("SECOPS_T", 10) == 10
