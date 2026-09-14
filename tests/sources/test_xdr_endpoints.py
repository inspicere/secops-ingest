"""Offline tests for the XDR endpoint snapshot connector.

This connector is a full snapshot rather than an incremental read, so the tests
assert the two properties that follow from that: the cursor is ignored, and
every row in a run shares one snapshot timestamp.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from secops_ingest.sources import _cortex
from secops_ingest.sources import xdr_endpoints as endpoints_mod
from secops_ingest.sources.xdr_endpoints import XdrEndpointsSource

FROZEN = "2026-09-14T00:00:00+00:00"


def endpoint(eid: str) -> dict[str, Any]:
    return {
        "endpoint_id": eid,
        "endpoint_name": "host",
        "endpoint_status": "CONNECTED",
        "agent_version": "8.4.0.1",
        "content_version": "1000-1000",
        "os_type": "AGENT_OS_WINDOWS",
        "last_seen": 1_789_400_000_000,
        "is_isolated": "AGENT_UNISOLATED",
        "operational_status": "PROTECTED",
    }


class Recorder:
    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        rows = self.pages.pop(0) if self.pages else []
        return {"reply": {"total_count": 3, "result_count": len(rows),
                          "endpoints": rows}}


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> XdrEndpointsSource:
    monkeypatch.setenv("SECOPS_XDR_ENDPOINTS_PAGE_SIZE", "2")
    monkeypatch.setattr(
        endpoints_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base=f"https://api-tenant.example.com{path}"))
    s = XdrEndpointsSource()
    s._snapshot_at = lambda: FROZEN  # type: ignore[method-assign]
    return s


def test_the_cursor_is_ignored_because_every_run_is_a_full_snapshot(
    source: XdrEndpointsSource,
) -> None:
    rec = Recorder([[endpoint("a"), endpoint("b")], [endpoint("c")]])
    source._post = rec  # type: ignore[method-assign]
    with_cursor = [r["endpoint_id"] for r in source.fetch({}, "2020-01-01T00:00:00+00:00")]
    rec2 = Recorder([[endpoint("a"), endpoint("b")], [endpoint("c")]])
    source._post = rec2  # type: ignore[method-assign]
    without = [r["endpoint_id"] for r in source.fetch({}, None)]
    assert with_cursor == without == ["a", "b", "c"]
    assert "filters" not in rec.bodies[0]["request_data"]


def test_every_row_in_a_run_shares_one_snapshot_time(
    source: XdrEndpointsSource,
) -> None:
    """One partition per snapshot, so policy drift becomes a time series
    instead of a current-state table that overwrites its own history.
    """
    rows = [source.to_row(endpoint(e), 1) for e in ("a", "b", "c")]
    assert {r[2] for r in rows} == {FROZEN}
    assert [r[0] for r in rows] == ["a", "b", "c"]


def test_the_watermark_is_the_snapshot_time(source: XdrEndpointsSource) -> None:
    assert source.watermark_of(endpoint("a")) == FROZEN


def test_paging_walks_the_window(source: XdrEndpointsSource) -> None:
    rec = Recorder([[endpoint("a"), endpoint("b")], [endpoint("c")]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    windows = [(b["request_data"]["search_from"], b["request_data"]["search_to"])
               for b in rec.bodies]
    assert windows == [(0, 2), (2, 4)]


def test_authenticate_resolves_the_secret_and_returns_standard_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The authenticate method must resolve the secret with the correct name and
    path, and return the standard headers with no nonce or timestamp."""
    monkeypatch.setenv("SECOPS_XDR_ENDPOINTS_SECRET", "xdr-endpoints-test-secret")
    resolve_args: list[tuple[str, str]] = []

    def mock_resolve(secret: str, path: str) -> _cortex.CortexCreds:
        resolve_args.append((secret, path))
        return _cortex.CortexCreds(
            key="test-key", key_id="42", base=f"https://api-tenant.example.com{path}")

    monkeypatch.setattr(endpoints_mod, "resolve", mock_resolve)
    source = XdrEndpointsSource()
    headers = source.authenticate()

    # Verify resolve was called with the correct arguments
    assert resolve_args == [("xdr-endpoints-test-secret", "/public_api/v1")]

    # Verify the returned headers are the standard set
    assert headers == {
        "Authorization": "test-key",
        "x-xdr-auth-id": "42",
        "Content-Type": "application/json",
    }
    # Ensure no nonce or timestamp headers
    assert "x-xdr-nonce" not in headers
    assert "x-xdr-timestamp" not in headers


def test_snapshot_time_is_pinned_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The snapshot time must be pinned on first call and reused for subsequent
    calls within the same run. This is critical: without pinning, a run spanning
    midnight would split one snapshot across two partitions."""
    monkeypatch.setattr(
        endpoints_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base=f"https://api-tenant.example.com{path}"))
    source = XdrEndpointsSource()

    # Call _snapshot_at twice and assert both return the exact same value
    first_call = source._snapshot_at()
    second_call = source._snapshot_at()
    assert first_call == second_call

    # Assert the value parses as an ISO-8601 timestamp with UTC offset
    from datetime import datetime
    parsed = datetime.fromisoformat(first_call)
    assert parsed.utcoffset() == timedelta(0)


def test_authenticate_starts_a_new_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling authenticate() must reset the pinned snapshot time so the next
    run starts with a fresh snapshot timestamp."""
    monkeypatch.setattr(
        endpoints_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base=f"https://api-tenant.example.com{path}"))
    source = XdrEndpointsSource()

    # Pin a value by calling _snapshot_at
    source._snapshot_at()
    assert source._pinned is not None

    # Call authenticate, which should reset _pinned
    source.authenticate()
    assert source._pinned is None
