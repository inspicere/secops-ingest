"""Offline tests for the DefectDojo connector.

No network. `_get` is replaced with a recorder, so the query parameters the
connector sends and its stop conditions are asserted directly.

Field names and shapes mirror a real DefectDojo v2 findings response; every
value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.common.http import RetryBudgetExhausted
from secops_ingest.sources.defectdojo import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_TIMEOUT_SEC,
    MIN_PAGE_SIZE,
    DefectDojoSource,
)


def finding(
    fid: int,
    updated: str | None,
    created: str = "2026-05-02T23:08:36-05:00",
    date: str | None = "2026-05-02",
) -> dict[str, Any]:
    return {
        "id": fid,
        "title": "synthetic finding",
        "severity": "High",
        "created": created,
        "date": date,
        "last_status_update": updated,
        "active": True,
        "is_mitigated": False,
    }


def page(records: list[dict[str, Any]], more: bool = False) -> dict[str, Any]:
    # The connector only tests `next` for truthiness — it paginates by offset —
    # but a realistic value is what the API actually returns, and example.com is
    # reserved by RFC 2606 for exactly this.
    nxt = "https://dojo.example.com/api/v2/findings/?limit=2&offset=2" if more else None
    return {"count": 999, "next": nxt, "results": records}


class Recorder:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.params: list[dict[str, Any]] = []

    def __call__(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
        self.params.append(params)
        return self.pages.pop(0) if self.pages else page([])


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> DefectDojoSource:
    """A source whose pages are tiny on BOTH paths.

    Both sizes are pinned, not just the incremental one. Tests here drive the
    backfill path by passing no cursor, and leaving the backfill size at its
    1000 default would make `offset` step by 1000 -- which says nothing about
    pagination and buries the behaviour under a number chosen for a live
    instance. Tests that care about the real defaults construct their own
    source and delete these.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "2")
    return DefectDojoSource()


def drive(
    src: DefectDojoSource, rec: Recorder, cursor: str | None = None
) -> list[dict[str, Any]]:
    src._get = rec  # type: ignore[method-assign]
    return list(src.fetch({"Authorization": "Token x"}, cursor))


# -- the two silent API traps -------------------------------------------------


def test_uses_o_not_ordering(source: DefectDojoSource) -> None:
    """`ordering=` is accepted and silently ignored by DefectDojo; `o=` works.

    Sending the conventional name would return the collection in arbitrary
    order, and the early stop would then cut the run at a random point.
    """
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
    drive(source, rec, cursor="2026-09-01T00:00:00-05:00")
    # The parameter NAME is the point here; which column it names is covered by
    # the backfill/incremental tests below.
    assert "o" in rec.params[0]
    assert "ordering" not in rec.params[0]


def test_sorts_descending(source: DefectDojoSource) -> None:
    """Ascending order would make the recorded watermark the OLDEST record."""
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
    drive(source, rec)
    assert rec.params[0]["o"].startswith("-")


# -- one ordering, one page size ----------------------------------------------
#
# These replace the backfill/incremental page-size split added a day earlier.
# That split was correct for a design with two orderings; this design has one,
# so the second size has nothing left to mean.


def test_always_sorts_by_id_never_by_modification_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unindexed ordering is gone, on both paths.

    `-last_status_update` has no index, so DefectDojo sorts ~52k rows per
    request: 51s for 25 records, measured from the host the connector runs on.
    `-id` is indexed and returns 1000 records in 5-13s. The scan reads
    everything either way, so the expensive ordering bought nothing but a
    cursor the server could not filter on anyway.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    src = DefectDojoSource()
    for cursor in (None, "2026-09-01T00:00:00-05:00"):
        rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
        drive(src, rec, cursor=cursor)
        assert rec.params[0]["o"] == "-id", f"cursor={cursor!r}"


def test_one_page_size_for_both_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """1000, because the worst page measured is 4.9 MB in 13.2s.

    Sampled across the id range at limit=200, pages run 0.4-1.9 MB; the heaviest
    region is the oldest ids. A 1000-record page there is 4.9 MB and 13.2s,
    which is 22% of the request timeout -- headroom for a heavier region
    appearing later, which is the thing page size cannot bound (payload size
    varies 100x per finding).
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.delenv("SECOPS_DEFECTDOJO_PAGE_SIZE", raising=False)
    src = DefectDojoSource()
    assert src.page_size == DEFAULT_PAGE_SIZE == 1000
    assert not hasattr(src, "backfill_page_size"), "the second size is gone"


def test_the_request_timeout_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    """It was hardcoded at 60s, which page size cannot protect.

    Bytes per page are unbounded regardless of record count, so the timeout is
    the only real guard and it has to be adjustable per deployment.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.delenv("SECOPS_DEFECTDOJO_TIMEOUT_SEC", raising=False)
    assert DefectDojoSource().timeout_sec == DEFAULT_TIMEOUT_SEC == 120
    monkeypatch.setenv("SECOPS_DEFECTDOJO_TIMEOUT_SEC", "45")
    assert DefectDojoSource().timeout_sec == 45


# -- the full scan, which replaces the early stop ------------------------------
#
# THE SEMANTICS BELOW ARE INVERTED FROM THE PREVIOUS DESIGN, DELIBERATELY. The
# connector used to sort by modification time descending and stop at the first
# record older than the cursor, because that was the only way to approximate a
# filter the API does not offer. Measured 2026-10-18, that stop was the problem:
# it could not finish. 58s per page against a 60s request timeout, 200 records
# in 11.5 minutes, killed by the unit timeout with its watermark unmoved -- so
# the next run repeated the same work forever.
#
# A full scan on the indexed ordering is CHEAPER than a partial scan on the
# unindexed one: ~5 minutes for all ~52k findings, against ~17 minutes to walk
# merely 500 changed records. So the scan no longer stops early; it reads
# everything and decides what to keep in process.


def test_a_record_older_than_the_cursor_does_not_end_the_scan(
    source: DefectDojoSource,
) -> None:
    """The inverse of the old contract, and the whole point of the change.

    Ordered by id, an old modification can sit anywhere in the collection, so
    stopping at the first one would truncate the scan at an arbitrary point.
    """
    rec = Recorder([
        page([finding(1, "2026-08-01T00:00:00-05:00"),   # older than the cursor
              finding(2, "2026-09-09T00:00:00-05:00")],  # newer, AFTER the old one
             more=True),
        page([finding(3, "2026-09-10T00:00:00-05:00")]),
    ])
    got = drive(source, rec, cursor="2026-09-01T00:00:00-05:00")

    assert [f["id"] for f in got] == [2, 3], "the old record is skipped, not fatal"
    assert len(rec.params) == 2, "and the scan continued to the next page"


def test_only_records_newer_than_the_cursor_are_yielded(
    source: DefectDojoSource,
) -> None:
    """Filtering in process is what keeps the database cost unchanged.

    The scan reads ~52k findings every run; landing them all would rewrite every
    row and churn ~140 MB of dead tuples per cycle. Only changed records are
    yielded, so Postgres still sees a handful of upserts.
    """
    rec = Recorder([
        page([finding(1, "2026-08-01T00:00:00-05:00"),
              finding(2, "2026-09-05T00:00:00-05:00"),
              finding(3, "2026-07-01T00:00:00-05:00")]),
    ])
    got = drive(source, rec, cursor="2026-09-01T00:00:00-05:00")
    assert [f["id"] for f in got] == [2]


def test_a_record_exactly_at_the_cursor_is_not_re_yielded(
    source: DefectDojoSource,
) -> None:
    """Strictly newer, and unlike the old design this drops no ties.

    The previous version stopped at `< cursor` so that ties AT the cursor were
    re-read, because stopping at `<=` would have dropped every tie except the
    one that set the watermark. A full scan has no such hazard: the run that set
    the watermark to M yielded every record at M, since all of them were newer
    than the cursor it started from. Excluding them now re-lands nothing.
    """
    rec = Recorder([page([finding(1, "2026-09-01T00:00:00-05:00")])])
    assert drive(source, rec, cursor="2026-09-01T00:00:00-05:00") == []


def test_a_first_run_yields_everything(source: DefectDojoSource) -> None:
    rec = Recorder([
        page([finding(1, "2026-01-01T00:00:00-05:00"),
              finding(2, "2026-09-09T00:00:00-05:00")]),
    ])
    assert [f["id"] for f in drive(source, rec, cursor=None)] == [1, 2]


def test_the_watermark_comes_from_the_highest_mark_yielded(
    source: DefectDojoSource,
) -> None:
    """Not from the first record, which is what descending order used to give.

    Ordered by id the newest modification can be anywhere, so the run's high
    mark is the maximum over what it yielded. The framework keeps the maximum it
    observes, so this is a property of the sequence rather than of its first
    element -- but it is the reason the old "first record sets the watermark"
    comment had to go.
    """
    rec = Recorder([
        page([finding(1, "2026-09-02T00:00:00-05:00"),
              finding(2, "2026-09-09T00:00:00-05:00"),
              finding(3, "2026-09-04T00:00:00-05:00")]),
    ])
    got = drive(source, rec, cursor="2026-09-01T00:00:00-05:00")
    marks = [source.watermark_of(f) for f in got]
    assert max(marks) == "2026-09-09T00:00:00-05:00"


# -- surviving a server that cannot keep up -----------------------------------
#
# MEASURED 2026-10-18 against a DefectDojo at load 48 with its memory
# exhausted: adjacent offsets returned 0.26 MB in 32s, then nothing in 150s,
# then 0.64 MB in 60s. The payloads were ordinary -- 100 findings totalling
# 1.2 MB, median 7.1 KB -- so the timeouts were the server, not the data.
#
# `with_retries` retries the IDENTICAL request, so a timed-out page times out
# again five times over. At a 120s timeout that is ten minutes of silence
# followed by a failed run, which is how a transient server problem became a
# fourteen-minute livelocked run. A timeout means "that was too much to ask
# for", so the answer is to ask for less, at the same offset.


class _TimeoutThenOk:
    """Times out while the page is larger than `ok_at`, then succeeds."""

    def __init__(self, ok_at: int, pages: list[dict[str, Any]]) -> None:
        self.ok_at = ok_at
        self.pages = pages
        self.params: list[dict[str, Any]] = []

    def __call__(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
        import httpx

        self.params.append(dict(params))
        if params["limit"] > self.ok_at:
            raise httpx.ReadTimeout("too much to ask for")
        return self.pages.pop(0) if self.pages else page([])


def test_a_timed_out_page_is_retried_smaller_at_the_same_offset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()
    rec = _TimeoutThenOk(250, [page([finding(1, "2026-09-09T00:00:00-05:00")])])
    got = drive(src, rec, cursor=None)

    assert [f["id"] for f in got] == [1]
    sizes = [p["limit"] for p in rec.params]
    assert sizes[0] == 1000, "it still tries the fast size first"
    assert sizes[-1] <= 250, "and shrinks until the server can answer"
    assert {p["offset"] for p in rec.params} == {0}, "never advancing past the gap"


def test_the_page_size_recovers_after_a_run_of_successes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reverses an earlier decision, on the strength of a measured run.

    This used to assert the opposite -- that a reduced size STUCK for the rest
    of the run -- reasoning that a server which refused 1000 should not be asked
    again. A full scan measured 2026-10-19 showed the tail running at 0.8s per
    25-record page: the server had recovered long before the end and was being
    asked for 25 anyway. That cost 1.8 minutes of a 39-minute run. Small, but it
    is pure waste and the reasoning behind it was wrong.

    Recovery is CAUTIOUS, because naive recovery is worse than stickiness: the
    slow band in that run was ~28 pages wide, and growing back after every few
    successes would have re-paid a timeout repeatedly while crossing it. So the
    threshold doubles each time a timeout happens, and a band that keeps
    refusing larger pages is asked progressively less often.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()
    # Times out above 250 for the FIRST call only, then serves anything.
    class _OnceSlow:
        def __init__(self) -> None:
            self.params: list[dict[str, Any]] = []
            self.failed = False
        def __call__(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
            import httpx
            self.params.append(dict(params))
            if not self.failed and params["limit"] > 250:
                self.failed = True
                raise httpx.ReadTimeout("once")
            more = len(self.params) < 12
            return page([finding(len(self.params), "2026-09-09T00:00:00-05:00")], more=more)

    rec = _OnceSlow()
    drive(src, rec, cursor=None)

    sizes = [p["limit"] for p in rec.params]
    assert sizes[0] == 1000
    assert 250 in sizes, "it shrank"
    assert sizes[-1] > 250, "and climbed back once the server was serving again"



def test_a_timeout_is_not_retried_at_the_same_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The single largest avoidable cost in the measured run.

    Six pages of the shrink ladder consumed 13.4 minutes of a 39-minute scan,
    because each size was attempted TWICE at a 120s timeout before shrinking.
    The second attempt is a request already known to be too large, so it buys
    nothing and costs a full timeout. Shrinking happens on the first timeout
    now; non-timeout failures keep their retries, which is what retries are for.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()
    rec = _TimeoutThenOk(250, [page([finding(1, "2026-09-09T00:00:00-05:00")])])
    drive(src, rec, cursor=None)

    attempts_at_1000 = [p for p in rec.params if p["limit"] == 1000]
    assert len(attempts_at_1000) == 1, "one attempt per size, then shrink"


def test_the_scan_covers_every_offset_with_no_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Offset continuity, which the size assertions above cannot see.

    This caught a real data-loss bug. When a page was served at one size and the
    policy then GREW the size, the caller advanced the offset by the new size
    rather than by the number of records actually served -- so a 250-record page
    at offset 750 was followed by offset 1750, and records 1000-1749 were never
    read. Nothing failed: the scan completed, the watermark advanced, and 750
    findings were silently missing.

    Every page's offset must equal the previous offset plus the records the
    previous page actually returned.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()

    class _SlowAbove250:
        """Serves `limit` records, timing out above 250 to force size changes."""

        def __init__(self) -> None:
            self.seen: list[tuple[int, int]] = []   # (offset, records served)
            self.served = 0

        def __call__(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
            import httpx
            if params["limit"] > 250:
                raise httpx.ReadTimeout("too large")
            n = params["limit"]
            self.seen.append((params["offset"], n))
            self.served += n
            recs = [finding(self.served + i, "2026-09-09T00:00:00-05:00")
                    for i in range(n)]
            return page(recs, more=self.served < 3000)

    rec = _SlowAbove250()
    drive(src, rec, cursor=None)

    expected = 0
    for off, served in rec.seen:
        assert off == expected, (
            f"offset {off} should have been {expected}: the previous page "
            f"served records the scan then skipped"
        )
        expected = off + served


def test_repeated_timeouts_make_growing_back_progressively_rarer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The doubling is what makes recovery safe, and nothing else tested it.

    Crossing a wide slow region, a fixed growth threshold retries the large page
    every few pages and re-pays a full timeout each time -- strictly worse than
    never growing at all. The measured band was ~28 pages wide, so a threshold
    of 4 would have cost roughly seven extra timeouts there.

    With doubling, attempts at the large size fall off geometrically. Asserted
    as a COUNT over many pages rather than by inspecting the threshold, so the
    test fails if the doubling is removed rather than merely restating it.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()

    class _AlwaysSlowAbove250:
        def __init__(self) -> None:
            self.params: list[dict[str, Any]] = []
        def __call__(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
            import httpx
            self.params.append(dict(params))
            if params["limit"] > 250:
                raise httpx.ReadTimeout("wide slow region")
            served = sum(1 for p in self.params if p["limit"] <= 250)
            return page([finding(served, "2026-09-09T00:00:00-05:00")],
                        more=served < 40)

    rec = _AlwaysSlowAbove250()
    drive(src, rec, cursor=None)

    big = [p for p in rec.params if p["limit"] > 250]
    assert len(big) <= 4, (
        f"grew back {len(big)} times across 40 pages; with a doubling "
        "threshold this should be a handful, not one every few pages"
    )
    assert len(big) >= 2, "but it should still try more than once"


def test_shrinking_stops_at_the_floor_and_the_run_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Below the floor, failing loudly beats shrinking to nothing.

    A page of one record that still times out is a broken server, not a large
    page, and pretending otherwise would walk the whole collection one timeout
    at a time.
    """
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", "1000")
    src = DefectDojoSource()
    rec = _TimeoutThenOk(0, [])  # never succeeds at any size

    with pytest.raises(RetryBudgetExhausted):
        drive(src, rec, cursor=None)

    # The LADDER is asserted, not `min(...) >= MIN_PAGE_SIZE` -- that compares
    # the sizes tried against the very constant under test, so it holds for any
    # floor and cannot fail. Pinning the concrete sequence fixes both the
    # divisor and the floor, and fails if either moves.
    assert sorted({p["limit"] for p in rec.params}, reverse=True) == [1000, 250, 62, 25]
    assert MIN_PAGE_SIZE == 25


def test_a_non_timeout_failure_is_not_shrunk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrinking a 500 would just ask a broken endpoint the same thing slower."""
    import httpx

    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")
    src = DefectDojoSource()

    calls: list[int] = []

    def boom(creds: Any, params: dict[str, Any]) -> dict[str, Any]:
        calls.append(params["limit"])
        raise httpx.HTTPStatusError(
            "bad request",
            request=httpx.Request("GET", "https://dojo.example.com"),
            response=httpx.Response(400),
        )

    with pytest.raises(httpx.HTTPStatusError):
        drive(src, boom, cursor=None)
    assert len(set(calls)) == 1, "one page size was tried, not a ladder"


# -- pagination ---------------------------------------------------------------


def test_paginates_by_offset_until_next_is_null(source: DefectDojoSource) -> None:
    rec = Recorder([
        page([finding(1, "2026-09-08T09:00:00-05:00"),
              finding(2, "2026-09-08T08:00:00-05:00")], more=True),
        page([finding(3, "2026-09-08T07:00:00-05:00")], more=False),
    ])
    got = drive(source, rec)
    assert [f["id"] for f in got] == [1, 2, 3]
    assert [p["offset"] for p in rec.params] == [0, 2]


def test_absent_next_ends_the_run(source: DefectDojoSource) -> None:
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")], more=False)])
    drive(source, rec)
    assert len(rec.params) == 1


def test_empty_result_set_ends_the_run(source: DefectDojoSource) -> None:
    rec = Recorder([page([], more=True)])
    assert drive(source, rec) == []
    assert len(rec.params) == 1


# -- watermark vs event time --------------------------------------------------


def test_watermark_is_modification_not_creation(source: DefectDojoSource) -> None:
    """The mistake this connector exists to avoid.

    A watermark on `created` reads each finding once, on the day it appears,
    and never sees the mitigation that follows months later.
    """
    f = finding(1, updated="2026-05-25T14:16:39-05:00", created="2026-05-02T23:08:36-05:00")
    assert source.watermark_of(f) == "2026-05-25T14:16:39-05:00"


def test_watermark_falls_back_to_created_when_never_updated(
    source: DefectDojoSource,
) -> None:
    """Null last_status_update means untouched since import, not "no time"."""
    f = finding(1, updated=None, created="2026-05-02T23:08:36-05:00")
    assert source.watermark_of(f) == "2026-05-02T23:08:36-05:00"


def test_event_time_is_immutable_not_the_watermark(source: DefectDojoSource) -> None:
    """_event_time is the partition key, so it must never change.

    Partitioning on the modification time would move a row between partitions
    every time somebody triaged the finding.
    """
    f = finding(1, updated="2026-05-25T14:16:39-05:00", date="2026-05-02")
    row = source.to_row(f, run_id=3)
    assert row[2] == "2026-05-02"
    assert row[2] != f["last_status_update"]


def test_event_time_falls_back_to_created_without_a_date(
    source: DefectDojoSource,
) -> None:
    f = finding(1, updated=None, date=None, created="2026-05-02T23:08:36-05:00")
    assert source.to_row(f, run_id=1)[2] == "2026-05-02T23:08:36-05:00"


def test_to_row_shape(source: DefectDojoSource) -> None:
    row = source.to_row(finding(42, "2026-09-08T08:00:00-05:00"), run_id=9)
    assert row[0] == "42"
    assert json.loads(row[1])["severity"] == "High"
    assert row[3] == 9


def test_dry_run_id_becomes_null(source: DefectDojoSource) -> None:
    assert source.to_row(finding(1, None), run_id=0)[3] is None


# -- configuration ------------------------------------------------------------


def test_authenticate_requires_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_DEFECTDOJO_URL", raising=False)
    with pytest.raises(ValueError, match="SECOPS_DEFECTDOJO_URL"):
        DefectDojoSource().authenticate()


def test_authenticate_builds_a_token_header_and_registers_the_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECOPS_DEFECTDOJO_URL", "https://dojo.example.com")

    class FakeProvider:
        def get(self, name: str) -> str:
            return "tok-not-real-abc"

    monkeypatch.setattr("secops_ingest.sources.defectdojo.get_provider", lambda: FakeProvider())
    headers = DefectDojoSource().authenticate()
    assert headers == {"Authorization": "Token tok-not-real-abc"}

    from secops_ingest.redaction import scrub

    assert "tok-not-real-abc" not in scrub("sending Token tok-not-real-abc")


@pytest.mark.parametrize("bad", ["0", "-5", "nope"])
def test_invalid_page_size_is_rejected(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("SECOPS_DEFECTDOJO_PAGE_SIZE", bad)
    with pytest.raises(ValueError, match="SECOPS_DEFECTDOJO_PAGE_SIZE"):
        DefectDojoSource()


def test_tls_verification_on_by_default(source: DefectDojoSource) -> None:
    assert source._tls_verify() is True


def test_ca_bundle_preferred_over_disabling(
    source: DefectDojoSource, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_DEFECTDOJO_INSECURE", "1")
    monkeypatch.setenv("SECOPS_DEFECTDOJO_CA_BUNDLE", "/etc/ssl/dojo.pem")
    assert source._tls_verify() == "/etc/ssl/dojo.pem"


def test_disabling_verification_warns(
    source: DefectDojoSource, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SECOPS_DEFECTDOJO_INSECURE", "1")
    monkeypatch.delenv("SECOPS_DEFECTDOJO_CA_BUNDLE", raising=False)
    with caplog.at_level("WARNING"):
        assert source._tls_verify() is False
    assert "TLS verification DISABLED" in caplog.text


# -- backfill uses a cheaper ordering -----------------------------------------


def test_backfill_orders_by_the_indexed_column(source: DefectDojoSource) -> None:
    """No cursor means no early stop, so the expensive ordering buys nothing.

    last_status_update is unindexed in DefectDojo: ordering on it costs ~43s per
    page against ~51k findings, versus ~0.5s ordering by id. Over a 2,000-page
    backfill that is a day against twenty minutes.
    """
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
    drive(source, rec, cursor=None)
    assert rec.params[0]["o"] == "-id"




def test_backfill_still_collects_every_record(source: DefectDojoSource) -> None:
    """Order does not affect completeness when nothing stops early.

    The watermark stays correct because the framework keeps the MAXIMUM
    watermark it observes, not the last one to arrive.
    """
    out_of_order = page([
        finding(3, "2026-09-01T00:00:00-05:00"),
        finding(1, "2026-09-08T08:00:00-05:00"),
    ], more=True)
    rec = Recorder([out_of_order, page([finding(2, "2026-09-05T00:00:00-05:00")])])
    got = drive(source, rec, cursor=None)
    assert sorted(r["id"] for r in got) == [1, 2, 3]
