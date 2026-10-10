"""Offline tests for shared Cortex auth and configuration.

No network and no Vault: the secret provider is replaced with a stub, so the
header set and the base-URL assembly are asserted directly.
"""

from __future__ import annotations

import hashlib
import time

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


# -- advanced keys ---------------------------------------------------------
#
# The module used to document, from a 2026-09-14 measurement, that "these
# tenants issue Standard keys" because advanced headers returned 401. That
# experiment could not distinguish a tenant refusing Advanced from a STANDARD
# key being sent with Advanced headers, which 401s either way. The XDR tenant
# now issues an Advanced key and Standard auth 401s against it.


def test_an_advanced_key_signs_the_request_instead_of_sending_it(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of an Advanced key: the key itself never goes on the wire.

    Authorization carries sha256(key + nonce + timestamp). Asserted against the
    nonce and timestamp the call actually produced, so the CONCATENATION ORDER
    is pinned -- that is the part that silently 401s if it is wrong.
    """
    monkeypatch.setenv("SECOPS_XDR_AUTH_MODE", "advanced")
    creds = _cortex.resolve("xdr", "/public_api/v1")
    h = _cortex.headers(creds)

    assert h["x-xdr-auth-id"] == "42"
    assert len(h["x-xdr-nonce"]) == 64
    expected = hashlib.sha256(
        ("k" * 128 + h["x-xdr-nonce"] + h["x-xdr-timestamp"]).encode()).hexdigest()
    assert h["Authorization"] == expected
    # The key must not appear anywhere in the header set.
    assert "k" * 128 not in "".join(h.values())


def test_the_advanced_timestamp_is_milliseconds_not_seconds(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A seconds-resolution timestamp is ~1000x too small and reads as wildly
    stale, which the tenant rejects as a replay rather than a bad key."""
    monkeypatch.setenv("SECOPS_XDR_AUTH_MODE", "advanced")
    creds = _cortex.resolve("xdr", "/public_api/v1")
    ts = int(_cortex.headers(creds)["x-xdr-timestamp"])
    now_ms = int(time.time() * 1000)
    assert abs(now_ms - ts) < 5_000


def test_advanced_auth_is_regenerated_on_every_call(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nonce and timestamp must be per REQUEST, not per run.

    A 90-day alerts backfill is thousands of requests over a long run; one
    nonce reused throughout is a replay, and one timestamp goes stale.
    """
    monkeypatch.setenv("SECOPS_XDR_AUTH_MODE", "advanced")
    creds = _cortex.resolve("xdr", "/public_api/v1")
    first, second = _cortex.headers(creds), _cortex.headers(creds)
    assert first["x-xdr-nonce"] != second["x-xdr-nonce"]
    assert first["Authorization"] != second["Authorization"]


def test_standard_is_still_the_default(stub: StubProvider) -> None:
    """No env, no change: every existing deployment keeps Standard auth."""
    creds = _cortex.resolve("xdr", "/public_api/v1")
    h = _cortex.headers(creds)
    assert h["Authorization"] == "k" * 128
    assert "x-xdr-nonce" not in h


def test_an_unknown_auth_mode_is_refused(
    stub: StubProvider, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Falling back to Standard on a typo would 401 against an Advanced tenant
    and look exactly like a bad credential."""
    monkeypatch.setenv("SECOPS_XDR_AUTH_MODE", "Advnaced")
    with pytest.raises(ValueError, match="SECOPS_XDR_AUTH_MODE"):
        _cortex.resolve("xdr", "/public_api/v1")


# -- per-request signing, across every Cortex connector --------------------


class _FakeResp:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return {}


@pytest.mark.parametrize("modname,clsname", [
    ("xdr", "XdrSource"),
    ("xdr_alerts", "XdrAlertsSource"),
    ("xdr_endpoints", "XdrEndpointsSource"),
    ("xsoar", "XsoarSource"),
])
def test_every_connector_signs_each_request_freshly(
    modname: str, clsname: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advanced auth must be rebuilt per request in EVERY connector.

    authenticate() is called once per run and its headers were reused for every
    page. In Standard mode that is correct and free. In Advanced mode it sends
    one nonce and one timestamp for the whole run -- a replay, and a stale clock.
    Parametrised because the fix is a one-line change in four places, which is
    exactly the shape of thing that gets applied to three of them.
    """
    import importlib

    import httpx

    mod = importlib.import_module(f"secops_ingest.sources.{modname}")
    monkeypatch.setenv("SECOPS_XDR_AUTH_MODE", "advanced")
    monkeypatch.setenv("SECOPS_XSOAR_AUTH_MODE", "advanced")
    monkeypatch.setattr(
        mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k" * 128, key_id="42",
            base=f"https://api-tenant.example.com{path}",
            auth_mode="advanced"))

    seen: list[dict[str, str]] = []

    def fake_post(url: str, **kw: object) -> _FakeResp:
        seen.append(dict(kw.get("headers") or {}))  # type: ignore[arg-type]
        return _FakeResp()

    monkeypatch.setattr(httpx, "post", fake_post)

    src = getattr(mod, clsname)()
    stale = src.authenticate()
    src._post(stale, {"request_data": {}})
    src._post(stale, {"request_data": {}})

    assert len(seen) == 2
    assert seen[0]["x-xdr-nonce"] != seen[1]["x-xdr-nonce"], (
        f"{modname} reused the nonce from authenticate()")
    assert "k" * 128 not in "".join(seen[0].values())
