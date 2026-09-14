"""Offline tests for the XSOAR connector.

No network. `_post` is replaced with a recorder, so the request bodies the
connector builds and the pagination it performs are asserted directly.

Field names mirror a real XSOAR 8 incidents/search response; every value is
synthetic.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.sources import _cortex
from secops_ingest.sources import xsoar as xsoar_mod
from secops_ingest.sources.xsoar import XsoarSource


def incident(iid: str, modified: str, created: str = "2026-01-02T03:04:05.000Z",
             closed: str | None = None) -> dict[str, Any]:
    return {
        "id": iid,
        "created": created,
        "modified": modified,
        "closed": closed or "0001-01-01T00:00:00Z",
        "status": 2,
        "severity": 3,
        "owner": "analyst",
        "type": "synthetic type",
        "sourceBrand": "Cortex XDR - IR",
        "dbotMirrorId": f"xdr-{iid}",
        "openDuration": 120,
    }


class Recorder:
    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        rows = self.pages.pop(0) if self.pages else []
        return {"total": 4, "data": rows}


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> XsoarSource:
    monkeypatch.setenv("SECOPS_XSOAR_PAGE_SIZE", "2")
    monkeypatch.setattr(xsoar_mod, "resolve",
                        lambda secret, path: _cortex.CortexCreds(
                            key="k", key_id="1",
                            base=f"https://api-tenant.example.com{path}"))
    return XsoarSource()


def test_fetch_pages_until_a_short_page(source: XsoarSource) -> None:
    rec = Recorder([[incident("1", "2026-09-01T00:00:00.000Z"),
                     incident("2", "2026-09-02T00:00:00.000Z")],
                    [incident("3", "2026-09-03T00:00:00.000Z")]])
    source._post = rec  # type: ignore[method-assign]
    got = list(source.fetch({}, None))
    assert [r["id"] for r in got] == ["1", "2", "3"]
    assert [b["filter"]["page"] for b in rec.bodies] == [0, 1]


def test_the_date_range_is_nested_inside_filter(source: XsoarSource) -> None:
    """A top-level fromDate is ACCEPTED AND SILENTLY IGNORED.

    Measured 2026-09-14: top-level returned the full 48,678-row collection;
    filter.fromDate returned 560. A connector built on the top-level form looks
    like it works while re-reading everything every run.
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, "2026-09-07T00:00:00.000Z"))
    body = rec.bodies[0]
    assert body["filter"]["fromDate"] == "2026-09-07T00:00:00.000Z"
    assert "fromDate" not in body


def test_no_filter_query_is_ever_sent(source: XsoarSource) -> None:
    """filter.query did not break paging when measured, but the hazard it is
    warned about is silent under-ingestion, and filter.fromDate costs nothing.
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, "2026-09-07T00:00:00.000Z"))
    assert "query" not in rec.bodies[0]["filter"]


def test_todate_is_pinned_once_for_the_whole_run(source: XsoarSource) -> None:
    """Without a pinned upper bound, records arriving mid-run shift the result
    set under the paging cursor and rows are skipped."""
    rec = Recorder([[incident("1", "2026-09-01T00:00:00.000Z"),
                     incident("2", "2026-09-02T00:00:00.000Z")],
                    [incident("3", "2026-09-03T00:00:00.000Z")]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    tos = {b["filter"]["toDate"] for b in rec.bodies}
    assert len(tos) == 1


def test_sort_is_ascending_on_modified(source: XsoarSource) -> None:
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    assert rec.bodies[0]["filter"]["sort"] == [{"field": "modified", "asc": True}]


def test_watermark_is_modified_not_created(source: XsoarSource) -> None:
    r = incident("1", "2026-09-09T00:00:00.000Z", created="2026-01-01T00:00:00.000Z")
    assert source.watermark_of(r) == "2026-09-09T00:00:00.000Z"


def test_event_time_is_created_because_the_partition_key_must_be_immutable(
    source: XsoarSource,
) -> None:
    r = incident("1", "2026-09-09T00:00:00.000Z", created="2026-01-01T00:00:00.000Z")
    source_id, _payload, event_time, run_id = source.to_row(r, 7)
    assert source_id == "1"
    assert event_time == "2026-01-01T00:00:00.000Z"
    assert run_id == 7


def test_to_row_uses_zero_run_id_as_null(source: XsoarSource) -> None:
    _sid, _p, _e, run_id = source.to_row(incident("1", "2026-09-09T00:00:00.000Z"), 0)
    assert run_id is None


def test_authenticate_resolves_the_secret_and_returns_standard_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The secret name and the API path are both wrong-able in ways nothing else
    catches: a wrong secret name resolves a different tenant's credentials, and
    a wrong path builds a base URL that 404s every request.

    XSOAR is on /xsoar/public/v1, not the /public_api/v1 the three XDR
    connectors share -- the single field that differs between them.
    """
    monkeypatch.setenv("SECOPS_XSOAR_SECRET", "xsoar-test-secret")
    resolve_args: list[tuple[str, str]] = []

    def mock_resolve(secret: str, path: str) -> _cortex.CortexCreds:
        resolve_args.append((secret, path))
        return _cortex.CortexCreds(
            key="test-key", key_id="42", base=f"https://api-tenant.example.com{path}")

    monkeypatch.setattr(xsoar_mod, "resolve", mock_resolve)
    headers = XsoarSource().authenticate()

    assert resolve_args == [("xsoar-test-secret", "/xsoar/public/v1")]
    assert headers == {
        "Authorization": "test-key",
        "x-xdr-auth-id": "42",
        "Content-Type": "application/json",
    }
    # Advanced auth 401s on these tenants; sending its fields is a regression.
    assert "x-xdr-nonce" not in headers
    assert "x-xdr-timestamp" not in headers
