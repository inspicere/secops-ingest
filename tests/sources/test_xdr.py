"""Offline tests for the Cortex XDR incidents connector.

No network. `_post` is replaced with a recorder, so the request bodies and the
paging arithmetic are asserted directly. Values are synthetic; field names and
the epoch-millisecond timestamps mirror a real get_incidents reply.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.sources import _cortex
from secops_ingest.sources import xdr as xdr_mod
from secops_ingest.sources.xdr import PAGE_CAP, XdrSource


def inc(iid: str, created: int, modified: int) -> dict[str, Any]:
    return {
        "incident_id": iid,
        "creation_time": created,
        "modification_time": modified,
        "status": "resolved_true_positive",
        "severity": "high",
        "alert_count": 3,
        "host_count": 1,
        "user_count": 1,
    }


class Recorder:
    def __init__(self, pages: list[list[dict[str, Any]]], total: int) -> None:
        self.pages = pages
        self.total = total
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        rows = self.pages.pop(0) if self.pages else []
        return {"reply": {"total_count": self.total, "result_count": len(rows),
                          "incidents": rows}}


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> XdrSource:
    monkeypatch.setenv("SECOPS_XDR_PAGE_SIZE", "2")
    monkeypatch.setattr(
        xdr_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base=f"https://api-tenant.example.com{path}"))
    return XdrSource()


def test_page_size_cannot_exceed_the_api_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """search_to - search_from above 100 returns HTTP 400. Measured 2026-09-14."""
    monkeypatch.setenv("SECOPS_XDR_PAGE_SIZE", "500")
    monkeypatch.setattr(
        xdr_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base="https://api-tenant.example.com/p"))
    assert XdrSource().page_size == PAGE_CAP


def test_fetch_walks_the_window_forward(source: XdrSource) -> None:
    rec = Recorder([[inc("1", 1_000, 2_000), inc("2", 1_100, 2_100)],
                    [inc("3", 1_200, 2_200)]], total=3)
    source._post = rec  # type: ignore[method-assign]
    got = list(source.fetch({}, None))
    assert [r["incident_id"] for r in got] == ["1", "2", "3"]
    windows = [(b["request_data"]["search_from"], b["request_data"]["search_to"])
               for b in rec.bodies]
    assert windows == [(0, 2), (2, 4)]


def bounds(body: dict[str, Any]) -> dict[str, Any]:
    """The modification_time filters of one request, keyed by operator."""
    return {f["operator"]: f["value"]
            for f in body["request_data"]["filters"]
            if f["field"] == "modification_time"}


def test_cursor_becomes_a_modification_time_filter(source: XdrSource) -> None:
    rec = Recorder([[]], total=0)
    source._post = rec  # type: ignore[method-assign]
    source._now_ms = lambda: 1_789_999_999_999  # type: ignore[method-assign]
    list(source.fetch({}, "1789000000000"))
    assert bounds(rec.bodies[0]) == {"gte": 1789000000000, "lte": 1_789_999_999_999}


def test_the_window_is_bounded_at_both_ends(source: XdrSource) -> None:
    """Sorting ascending on the same field being filtered, with offset paging,
    means an incident touched mid-scan moves to the end of the sort and shifts
    every later row forward -- so a row is stepped over at the next page
    boundary. It is then below the watermark this run advances to, so no later
    run asks for it either. The upper bound makes the result set stable.
    """
    rec = Recorder([[]], total=0)
    source._post = rec  # type: ignore[method-assign]
    source._now_ms = lambda: 1_789_999_999_999  # type: ignore[method-assign]
    list(source.fetch({}, "1789000000000"))
    assert set(bounds(rec.bodies[0])) == {"gte", "lte"}


def test_only_the_upper_bound_is_sent_without_a_cursor(source: XdrSource) -> None:
    """A first run is unbounded below on purpose -- it is a backfill -- but it
    is the longest scan there is, so it needs the upper bound most."""
    rec = Recorder([[]], total=0)
    source._post = rec  # type: ignore[method-assign]
    source._now_ms = lambda: 1_789_999_999_999  # type: ignore[method-assign]
    list(source.fetch({}, None))
    assert bounds(rec.bodies[0]) == {"lte": 1_789_999_999_999}


def test_the_upper_bound_is_pinned_once_for_the_whole_run(source: XdrSource) -> None:
    """Recomputing the bound per page would defeat it entirely: each request
    would admit whatever was modified since the previous one, which is the
    moving result set the bound exists to prevent.

    The clock ticks on every read here, so a per-page bound shows up as more
    than one distinct value rather than passing by coincidence.
    """
    ticking = iter([1_000, 2_000, 3_000, 4_000, 5_000])
    source._now_ms = lambda: next(ticking)  # type: ignore[method-assign]
    rec = Recorder([[inc("1", 1, 2), inc("2", 3, 4)], [inc("3", 5, 6)]], total=3)
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    assert len(rec.bodies) == 2, "the test must actually page to mean anything"
    assert len({bounds(b)["lte"] for b in rec.bodies}) == 1


def test_sort_is_ascending_on_modification_time(source: XdrSource) -> None:
    rec = Recorder([[]], total=0)
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    assert rec.bodies[0]["request_data"]["sort"] == {
        "field": "modification_time", "keyword": "asc"}


def test_watermark_is_modification_time(source: XdrSource) -> None:
    """A creation_time watermark ingests each incident once, while open, and
    never sees it resolve. Measured: a 7-day window returns 549 incidents by
    modification_time against 545 by creation_time -- those 4 are resolutions.
    """
    assert source.watermark_of(inc("1", 1_000, 2_000)) == 2_000


def test_event_time_converts_epoch_ms_from_creation_time(source: XdrSource) -> None:
    from datetime import UTC, datetime

    source_id, _payload, event_time, run_id = source.to_row(
        inc("1", 1_789_405_920_000, 1_789_500_000_000), 5)
    assert source_id == "1"
    assert event_time == datetime.fromtimestamp(1_789_405_920, tz=UTC)
    assert run_id == 5


def test_event_time_is_not_derived_from_the_watermark_field(source: XdrSource) -> None:
    """The partition key must be immutable or rows migrate between partitions."""
    from datetime import UTC, datetime

    _sid, _p, event_time, _r = source.to_row(inc("1", 1_000_000, 9_999_000_000), 1)
    assert event_time == datetime.fromtimestamp(1_000, tz=UTC)


def test_authenticate_resolves_the_secret_and_returns_standard_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The authenticate method must resolve the secret with the correct name and
    path, and return the standard headers with no nonce or timestamp."""
    monkeypatch.setenv("SECOPS_XDR_SECRET", "xdr-test-secret")
    resolve_args: list[tuple[str, str]] = []

    def mock_resolve(secret: str, path: str) -> _cortex.CortexCreds:
        resolve_args.append((secret, path))
        return _cortex.CortexCreds(
            key="test-key", key_id="42", base=f"https://api-tenant.example.com{path}")

    monkeypatch.setattr(xdr_mod, "resolve", mock_resolve)
    source = XdrSource()
    headers = source.authenticate()

    # Verify resolve was called with the correct arguments
    assert resolve_args == [("xdr-test-secret", "/public_api/v1")]

    # Verify the returned headers are the standard set
    assert headers == {
        "Authorization": "test-key",
        "x-xdr-auth-id": "42",
        "Content-Type": "application/json",
    }
    # Ensure no nonce or timestamp headers
    assert "x-xdr-nonce" not in headers
    assert "x-xdr-timestamp" not in headers
