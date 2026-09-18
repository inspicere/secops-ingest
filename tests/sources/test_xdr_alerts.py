"""Offline tests for the Cortex XDR alerts connector.

No network. `_post` is replaced with a recorder. The two behaviours that matter
here and nowhere else -- the bounded first run and the late-arrival overlap --
are asserted against a frozen clock.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.sources import _cortex
from secops_ingest.sources import xdr_alerts as alerts_mod
from secops_ingest.sources.xdr_alerts import (
    DEFAULT_BACKFILL_DAYS,
    XdrAlertsSource,
)

NOW_MS = 1_789_400_000_000


def alert(aid: str, detected: int) -> dict[str, Any]:
    return {
        "alert_id": aid,
        "detection_timestamp": detected,
        "local_insert_ts": detected + 139_000,
        "severity": "low",
        "category": "Hash",
        "source": "XDR IOC",
        "resolution_status": "STATUS_010_NEW",
        "endpoint_id": "e" * 32,
    }


class Recorder:
    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        rows = self.pages.pop(0) if self.pages else []
        return {"reply": {"total_count": 9, "result_count": len(rows), "alerts": rows}}


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> XdrAlertsSource:
    monkeypatch.setenv("SECOPS_XDR_ALERTS_PAGE_SIZE", "2")
    monkeypatch.setenv("SECOPS_XDR_ALERTS_LAG_SECONDS", "1800")
    monkeypatch.setattr(
        alerts_mod, "resolve",
        lambda secret, path: _cortex.CortexCreds(
            key="k", key_id="1", base=f"https://api-tenant.example.com{path}"))
    s = XdrAlertsSource()
    s._now_ms = lambda: NOW_MS  # type: ignore[method-assign]
    return s


def test_an_empty_watermark_starts_at_the_bounded_horizon_not_the_beginning(
    source: XdrAlertsSource,
) -> None:
    """2,650,762 alerts exist. Reading them all is ~26,500 requests and ~5GB.

    This is the one connector where "no watermark" must not mean "everything".
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    flt = rec.bodies[0]["request_data"]["filters"][0]
    expected = NOW_MS - DEFAULT_BACKFILL_DAYS * 86_400_000
    assert flt == {"field": "creation_time", "operator": "gte", "value": expected}


def test_the_cursor_is_rewound_by_the_lag_window(source: XdrAlertsSource) -> None:
    """local_insert_ts trails detection_timestamp by up to 627s (measured over
    100 alerts: min 7s, median 139s, max 627s). An alert indexed after the
    watermark has passed its detection time would be stepped over forever.
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, str(NOW_MS)))
    flt = rec.bodies[0]["request_data"]["filters"][0]
    assert flt["value"] == NOW_MS - 1_800_000


def test_the_filter_field_is_creation_time_not_a_payload_field_name(
    source: XdrAlertsSource,
) -> None:
    """detection_timestamp and local_insert_ts are payload fields, NOT filter
    fields -- using either as a filter field returns HTTP 500. Measured.
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, str(NOW_MS)))
    assert rec.bodies[0]["request_data"]["filters"][0]["field"] == "creation_time"


def test_fetch_pages_until_a_short_page(source: XdrAlertsSource) -> None:
    rec = Recorder([[alert("1", NOW_MS), alert("2", NOW_MS + 1)],
                    [alert("3", NOW_MS + 2)]])
    source._post = rec  # type: ignore[method-assign]
    assert [r["alert_id"] for r in source.fetch({}, None)] == ["1", "2", "3"]


def test_watermark_and_event_time_are_both_detection_timestamp(
    source: XdrAlertsSource,
) -> None:
    """Alerts are append-only in the fields this connector can filter on, so
    unlike the incident connectors there is no separate modification field.
    """
    from datetime import UTC, datetime

    a = alert("1", 1_789_405_920_000)
    assert source.watermark_of(a) == 1_789_405_920_000
    sid, _payload, event_time, run_id = source.to_row(a, 3)
    assert sid == "1"
    assert event_time == datetime.fromtimestamp(1_789_405_920, tz=UTC)
    assert run_id == 3


def test_authenticate_resolves_the_secret_and_returns_standard_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The authenticate method must resolve the secret with the correct name and
    path, and return the standard headers with no nonce or timestamp."""
    monkeypatch.setenv("SECOPS_XDR_ALERTS_SECRET", "xdr-alerts-test-secret")
    resolve_args: list[tuple[str, str]] = []

    def mock_resolve(secret: str, path: str) -> _cortex.CortexCreds:
        resolve_args.append((secret, path))
        return _cortex.CortexCreds(
            key="test-key", key_id="42", base=f"https://api-tenant.example.com{path}")

    monkeypatch.setattr(alerts_mod, "resolve", mock_resolve)
    source = XdrAlertsSource()
    headers = source.authenticate()

    # Verify resolve was called with the correct arguments
    assert resolve_args == [("xdr-alerts-test-secret", "/public_api/v1")]

    # Verify the returned headers are the standard set
    assert headers == {
        "Authorization": "test-key",
        "x-xdr-auth-id": "42",
        "Content-Type": "application/json",
    }
    # Ensure no nonce or timestamp headers
    assert "x-xdr-nonce" not in headers
    assert "x-xdr-timestamp" not in headers
