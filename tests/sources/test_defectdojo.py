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

from secops_ingest.sources.defectdojo import DefectDojoSource


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
    drive(source, rec)
    assert rec.params[0]["o"] == "-last_status_update"
    assert "ordering" not in rec.params[0]


def test_sorts_descending(source: DefectDojoSource) -> None:
    """Ascending order would make the recorded watermark the OLDEST record."""
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
    drive(source, rec)
    assert rec.params[0]["o"].startswith("-")


# -- the early stop, which replaces the time filter the API lacks -------------


def test_stops_at_the_first_record_older_than_the_cursor(
    source: DefectDojoSource,
) -> None:
    newer = finding(1, "2026-09-08T08:00:00-05:00")
    older = finding(2, "2026-09-01T08:00:00-05:00")
    rec = Recorder([page([newer, older], more=True)])
    got = drive(source, rec, cursor="2026-09-05T00:00:00-05:00")

    assert [f["id"] for f in got] == [1]
    assert len(rec.params) == 1, "must not request another page after the stop"


def test_ties_at_the_cursor_are_re_read_not_dropped(source: DefectDojoSource) -> None:
    """A bulk import gives many findings the same modification time.

    Stopping at `<= cursor` would drop every tie except the one that set the
    watermark. Re-reading them is free: landing is an upsert.
    """
    at_cursor = "2026-09-08T08:15:35-05:00"
    rec = Recorder([page([finding(1, at_cursor), finding(2, at_cursor)])])
    got = drive(source, rec, cursor=at_cursor)
    assert [f["id"] for f in got] == [1, 2]


def test_first_run_reads_from_the_top(source: DefectDojoSource) -> None:
    rec = Recorder([page([finding(1, "2026-09-08T08:00:00-05:00")])])
    got = drive(source, rec, cursor=None)
    assert [f["id"] for f in got] == [1]
    assert rec.params[0]["offset"] == 0


def test_descending_order_means_the_first_record_sets_the_watermark(
    source: DefectDojoSource,
) -> None:
    """The run's watermark is the high-water mark as of the scan's start.

    Anything modified while the scan is running is newer than that, so it is
    caught by the next run instead of being missed.
    """
    rec = Recorder([page([
        finding(1, "2026-09-08T08:00:00-05:00"),
        finding(2, "2026-09-07T08:00:00-05:00"),
    ])])
    got = drive(source, rec)
    marks = [source.watermark_of(f) for f in got]
    assert marks == sorted(marks, reverse=True)


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
