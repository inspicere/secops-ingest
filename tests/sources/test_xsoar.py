"""Offline tests for the XSOAR connector.

No network. `_post` is replaced with a recorder, so the request bodies the
connector builds and the pagination it performs are asserted directly.

Field names mirror a real XSOAR 8 incidents/search response; every value is
synthetic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

# Needs the 'http' extra: the Cortex connectors reach httpx through common.http.
pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.sources import _cortex  # noqa: E402
from secops_ingest.sources import xsoar as xsoar_mod  # noqa: E402
from secops_ingest.sources.xsoar import XsoarSource  # noqa: E402


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
    # The window now rides in filter.query (the date keys filter on `created` --
    # see the module docstring), but the NESTING finding is unchanged and is
    # what this test exists to protect: top level is accepted and ignored.
    assert "2026-09-07T00:00:00" in body["filter"]["query"]
    assert "query" not in body
    assert "fromDate" not in body


def test_filter_query_is_what_carries_the_window(source: XsoarSource) -> None:
    """REVERSES an earlier decision, so the reason is recorded here.

    This test used to assert the opposite -- that filter.query is never sent --
    on the grounds that "filter.query did not break paging when measured, but
    the hazard it is warned about is silent under-ingestion, and
    filter.fromDate costs nothing."

    The first half still holds: paging with query was re-measured on 2026-10-15
    and works (4 pages of 10, 40 distinct ids, no duplicates). The second half
    is false. filter.fromDate costs every update to an incident created before
    the window -- measured silent under-ingestion, which is the exact hazard the
    old reasoning was trying to avoid. The trade therefore inverts: query is now
    the safe option and fromDate is the dangerous one.
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, "2026-09-07T00:00:00.000Z"))
    assert "query" in rec.bodies[0]["filter"]


def test_the_upper_bound_is_pinned_once_for_the_whole_run(source: XsoarSource) -> None:
    """Without a pinned upper bound, records arriving mid-run shift the result
    set under the paging cursor and rows are skipped.

    The bound moved from filter.toDate into filter.query when the window moved
    onto the `modified` axis; the hazard and the guarantee are unchanged."""
    rec = Recorder([[incident("1", "2026-09-01T00:00:00.000Z"),
                     incident("2", "2026-09-02T00:00:00.000Z")],
                    [incident("3", "2026-09-03T00:00:00.000Z")]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    tos = {b["filter"]["query"].split("modified:<=")[1] for b in rec.bodies}
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


FROZEN = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)


def test_an_empty_watermark_starts_at_the_bounded_horizon_not_the_beginning(
    source: XsoarSource,
) -> None:
    """The live tenant holds incidents back to 2022-04-11.

    Without a floor, the first run asked for the whole collection and died
    landing its first row: CheckViolation, no partition of relation "incidents"
    for _event_time 2022-04-11. The warehouse partitions a five-month window on
    purpose, so "no watermark" must not mean "everything ever".
    """
    source._now = lambda: FROZEN  # type: ignore[method-assign]
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, None))
    expected = (FROZEN - timedelta(days=xsoar_mod.DEFAULT_BACKFILL_DAYS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    # Now the lower bound of the query range rather than filter.fromDate.
    assert f'modified:>="{expected}"' in rec.bodies[0]["filter"]["query"]


def test_the_backfill_horizon_is_not_reapplied_to_a_real_cursor(
    source: XsoarSource,
) -> None:
    """RENAMED. It used to say "used verbatim and not floored", which is no
    longer accurate: a cursor IS floored, to the second resolution the query
    comparison understands.

    The guarantee it was actually protecting is untouched and is what is
    asserted here -- the backfill HORIZON applies to a first run only. Re-applying
    it to a real watermark would re-read the whole horizon every run, which on
    this feed is the difference between a 30-second run and a quarter of
    history. Sub-second truncation is a separate, much smaller thing, and it
    floors; see test_a_subsecond_cursor_is_floored_not_rejected.
    """
    source._now = lambda: FROZEN  # type: ignore[method-assign]
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    list(source.fetch({}, "2026-10-01T00:00:00Z"))
    assert 'modified:>="2026-10-01T00:00:00Z"' in rec.bodies[0]["filter"]["query"]


def test_the_window_is_bounded_on_modified_not_created(source: XsoarSource) -> None:
    """fromDate/toDate filter on CREATED. The connector watermarks on MODIFIED.

    Those two axes diverge permanently, and the consequence is silent data loss:
    an incident created before the cursor and modified after it is never
    returned, so its update is never ingested. Measured against the live tenant
    on 2026-10-15 -- of 200 incidents in a 90-day window, 3 were created over a
    day ago and modified within the last day, and `fromDate = now - 1d` returned
    none of them. This is the same failure xdr.py documents and fixes for XDR.

    The fix bounds the window on the axis the connector actually tracks, via
    filter.query. Verified against the tenant before implementing: the bounded
    form returns 260 incidents with ascending sort honoured, includes an
    incident created before the window, and pages correctly -- 4 pages of 10,
    40 distinct ids, no duplicates. (`fromDateModified` was also tried and is
    silently ignored: it returned the entire 50,754-incident collection.)
    """
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    source._now = lambda: FROZEN  # type: ignore[method-assign]
    list(source.fetch({}, "2026-10-01T00:00:00.000Z"))

    flt = rec.bodies[0]["filter"]
    # Both created-axis keys must be gone. Leaving either re-imposes the bug on
    # whichever bound still carries it.
    assert "fromDate" not in flt, "fromDate filters on created and must not be sent"
    assert "toDate" not in flt, "toDate filters on created and must not be sent"

    q = flt["query"]
    assert "modified:>=" in q
    assert "modified:<=" in q
    assert "2026-10-01T00:00:00" in q


def test_a_subsecond_cursor_is_floored_not_rejected(source: XsoarSource) -> None:
    """XSOAR stamps `modified` with sub-second precision; the query comparison
    is second-resolution. Truncating FLOORS the lower bound, so the boundary
    second is re-read and the upsert absorbs it. Rounding up would skip."""
    rec = Recorder([[]])
    source._post = rec  # type: ignore[method-assign]
    source._now = lambda: FROZEN  # type: ignore[method-assign]
    list(source.fetch({}, "2026-10-01T12:34:56.789456123Z"))
    q = rec.bodies[0]["filter"]["query"]
    assert "2026-10-01T12:34:56Z" in q, q
    assert "789" not in q


def test_a_departure_mid_scan_stops_before_the_page_that_may_be_shifted(
    source: XsoarSource,
) -> None:
    """V-09, as in test_xdr: `total` can only fall inside a pinned window, and
    only because a row left it and shifted the rest forward."""
    from secops_ingest.common import context

    replies = iter([
        {"total": 5, "data": [incident("1", "2026-01-01T00:00:01Z"),
                              incident("2", "2026-01-01T00:00:02Z")]},
        {"total": 4, "data": [incident("4", "2026-01-01T00:00:04Z"),
                              incident("5", "2026-01-01T00:00:05Z")]},
    ])
    source._post = lambda creds, body: next(replies)  # type: ignore[method-assign]

    ctx = context.RunContext(source="xsoar")
    with context.running(ctx):
        got = [r["id"] for r in source.fetch({}, "2026-01-01T00:00:00Z")]

    assert got == ["1", "2"]
    assert ctx.partial and "5 -> 4" in ctx.partial[0]
