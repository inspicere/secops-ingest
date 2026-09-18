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


def test_resolve_registers_the_tenant_host_for_redaction(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tenant FQDN is the identifier this platform keeps out of the repo --
    and httpx logs the full request URL at INFO, which cli.py enables by
    default. RedactingFilter only scrubs values that were registered, so
    without this the hostname is written to the journal on every request.

    Registering it also neutralises CortexCreds' default __repr__, which prints
    `base` verbatim into any traceback carrying the dataclass.
    """
    seen: list[str] = []
    monkeypatch.setattr(_cortex, "register_secret", seen.append)
    creds = _cortex.resolve("xdr", "/p")
    assert "api-tenant.example.com" in seen
    # And it is the host actually used, not some other spelling of it.
    assert "api-tenant.example.com" in creds.base


def test_the_registered_host_is_the_one_after_the_api_prefix_is_added(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registering the stored value rather than the assembled one would leave
    the host that actually appears in every URL unredacted."""
    p = StubProvider({"x.api_key": "k" * 128, "x.api_key_id": "1",
                      "x.url": "https://tenant.example.com"})
    monkeypatch.setattr(_cortex, "get_provider", lambda: p)
    seen: list[str] = []
    monkeypatch.setattr(_cortex, "register_secret", seen.append)
    _cortex.resolve("x", "/p")
    assert "api-tenant.example.com" in seen


def test_a_registered_host_is_actually_scrubbed_from_a_log_line(
    stub: StubProvider,
) -> None:
    """End to end through the real registry: an httpx-shaped INFO line carrying
    the request URL must come out with the tenant removed."""
    import logging

    from secops_ingest import redaction

    # The registry is process-wide by design. Snapshot and restore it, or this
    # test silently changes what every later test's logs look like.
    before = set(redaction._REGISTRY)
    try:
        creds = _cortex.resolve("xdr", "/public_api/v1")
        record = logging.LogRecord(
            "httpx", logging.INFO, __file__, 1,
            'HTTP Request: POST %s "HTTP/1.1 200 OK"',
            (f"{creds.base}/incidents/get_incidents/",), None,
        )
        redaction.RedactingFilter().filter(record)
        assert "api-tenant.example.com" not in record.getMessage()
        assert redaction.PLACEHOLDER in record.getMessage()
    finally:
        redaction._REGISTRY.clear()
        redaction._REGISTRY.update(before)


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
