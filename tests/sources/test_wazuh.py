"""Offline tests for the Wazuh connector.

No network. `_search` is replaced with a recorder, so the query bodies the
connector builds and the pagination it performs are both asserted directly.

Field names mirror a real Wazuh alert document (schema only — every value here
is synthetic).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.sources.wazuh import WazuhSource


def alert(alert_id: str, ts: str, level: int = 5) -> dict[str, Any]:
    return {
        "id": alert_id,
        "timestamp": ts,
        "rule": {"level": level, "description": "synthetic", "id": "1002"},
        "agent": {"id": "001", "name": "host-a"},
        "location": "/var/log/syslog",
    }


def as_hits(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "hits": {
            "hits": [
                {"_id": f"idx-{r['id']}", "_source": r, "sort": [r["timestamp"], f"idx-{r['id']}"]}
                for r in records
            ]
        }
    }


class Recorder:
    """Stands in for the HTTP call and records every request body."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        return self.pages.pop(0) if self.pages else {"hits": {"hits": []}}


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> WazuhSource:
    monkeypatch.setenv("SECOPS_WAZUH_URL", "https://127.0.0.1:9200")
    monkeypatch.setenv("SECOPS_WAZUH_PAGE_SIZE", "2")
    monkeypatch.setenv("SECOPS_WAZUH_LAG_SECONDS", "900")
    return WazuhSource()


def drive(source: WazuhSource, rec: Recorder) -> list[dict[str, Any]]:
    source._search = rec  # type: ignore[method-assign]
    return list(source.fetch(("admin", "pw"), None))


def test_first_run_reads_everything(source: WazuhSource) -> None:
    rec = Recorder([as_hits([alert("a", "2026-09-08T10:00:00.000+0000")])])
    drive(source, rec)
    assert rec.bodies[0]["query"] == {"match_all": {}}


def test_sort_is_a_total_order(source: WazuhSource) -> None:
    """Sorting on timestamp alone skips or repeats rows sharing a millisecond."""
    rec = Recorder([as_hits([alert("a", "2026-09-08T10:00:00.000+0000")])])
    drive(source, rec)
    assert rec.bodies[0]["sort"] == [{"timestamp": "asc"}, {"_id": "asc"}]


def test_pagination_threads_search_after(source: WazuhSource) -> None:
    page1 = as_hits([
        alert("a", "2026-09-08T10:00:00.000+0000"),
        alert("b", "2026-09-08T10:00:01.000+0000"),
    ])
    page2 = as_hits([alert("c", "2026-09-08T10:00:02.000+0000")])
    rec = Recorder([page1, page2])
    got = drive(source, rec)

    assert [r["id"] for r in got] == ["a", "b", "c"]
    assert "search_after" not in rec.bodies[0]
    # Continues from the LAST hit of the previous page, not an offset.
    assert rec.bodies[1]["search_after"] == ["2026-09-08T10:00:01.000+0000", "idx-b"]


def test_short_page_ends_the_run_without_another_request(source: WazuhSource) -> None:
    rec = Recorder([as_hits([alert("a", "2026-09-08T10:00:00.000+0000")])])
    drive(source, rec)
    assert len(rec.bodies) == 1, "a short page means the end; asking again wastes a round trip"


def test_cursor_is_rewound_by_the_overlap(source: WazuhSource) -> None:
    """The query must start BEFORE the watermark, or late alerts are lost.

    Wazuh alerts are append-only, so the event time is also the watermark. An
    agent that was offline can index an alert older than a watermark we already
    passed; a strict `> cursor` query would never see it.
    """
    rec = Recorder([{"hits": {"hits": []}}])
    source._search = rec  # type: ignore[method-assign]
    list(source.fetch(("admin", "pw"), "2026-09-08T10:15:00+00:00"))

    gte = rec.bodies[0]["query"]["range"]["timestamp"]["gte"]
    assert gte.startswith("2026-09-08T10:00:00"), gte  # 15 minutes earlier


def test_overlap_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_WAZUH_URL", "https://127.0.0.1:9200")
    monkeypatch.setenv("SECOPS_WAZUH_LAG_SECONDS", "60")
    s = WazuhSource()
    rec = Recorder([{"hits": {"hits": []}}])
    s._search = rec  # type: ignore[method-assign]
    list(s.fetch(("admin", "pw"), "2026-09-08T10:15:00+00:00"))
    assert rec.bodies[0]["query"]["range"]["timestamp"]["gte"].startswith("2026-09-08T10:14:00")


def test_unparsable_watermark_raises_rather_than_reading_everything(
    source: WazuhSource,
) -> None:
    """Falling back to match_all on a bad cursor is a self-inflicted outage."""
    with pytest.raises(ValueError, match="ISO-8601"):
        list(source.fetch(("admin", "pw"), "not-a-timestamp"))


def test_alert_id_preferred_over_indexer_id(source: WazuhSource) -> None:
    rec = Recorder([as_hits([alert("real-id", "2026-09-08T10:00:00.000+0000")])])
    got = drive(source, rec)
    assert got[0]["id"] == "real-id"


def test_indexer_id_used_when_the_alert_has_none(source: WazuhSource) -> None:
    doc = alert("x", "2026-09-08T10:00:00.000+0000")
    del doc["id"]
    rec = Recorder([{"hits": {"hits": [{"_id": "fallback", "_source": doc, "sort": ["t", "f"]}]}}])
    got = drive(source, rec)
    assert got[0]["id"] == "fallback"


def test_missing_sort_key_stops_instead_of_guessing(source: WazuhSource) -> None:
    page = {"hits": {"hits": [
        {"_id": "i1", "_source": alert("a", "2026-09-08T10:00:00.000+0000")},
        {"_id": "i2", "_source": alert("b", "2026-09-08T10:00:01.000+0000")},
    ]}}
    rec = Recorder([page, as_hits([alert("c", "2026-09-08T10:00:02.000+0000")])])
    got = drive(source, rec)
    assert [r["id"] for r in got] == ["a", "b"]
    assert len(rec.bodies) == 1, "must not continue without a deterministic cursor"


def test_to_row_uses_event_time_not_the_watermark(source: WazuhSource) -> None:
    rec = alert("a", "2026-09-08T10:00:00.000+0000")
    row = source.to_row(rec, run_id=7)
    assert row[0] == "a"
    assert json.loads(row[1])["rule"]["level"] == 5
    assert row[2] == "2026-09-08T10:00:00.000+0000"
    assert row[3] == 7


def test_dry_run_id_becomes_null(source: WazuhSource) -> None:
    """run_id 0 is the dry-run sentinel and must not land as a real reference."""
    assert source.to_row(alert("a", "2026-09-08T10:00:00.000+0000"), run_id=0)[3] is None


def test_watermark_is_the_alert_timestamp(source: WazuhSource) -> None:
    assert source.watermark_of(alert("a", "2026-09-08T10:00:00.000+0000")) == (
        "2026-09-08T10:00:00.000+0000"
    )


def test_authenticate_requires_a_configured_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_WAZUH_URL", raising=False)
    with pytest.raises(ValueError, match="SECOPS_WAZUH_URL"):
        WazuhSource().authenticate()


def test_authenticate_registers_the_password_for_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECOPS_WAZUH_URL", "https://127.0.0.1:9200")

    class FakeProvider:
        def get(self, name: str) -> str:
            return "hunter2-not-real"

    monkeypatch.setattr("secops_ingest.sources.wazuh.get_provider", lambda: FakeProvider())
    user, password = WazuhSource().authenticate()
    assert (user, password) == ("admin", "hunter2-not-real")

    from secops_ingest.redaction import scrub

    assert "hunter2-not-real" not in scrub("connecting with hunter2-not-real")


@pytest.mark.parametrize("bad", ["0", "-1", "abc"])
def test_invalid_numeric_config_is_rejected(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv("SECOPS_WAZUH_PAGE_SIZE", bad)
    with pytest.raises(ValueError, match="SECOPS_WAZUH_PAGE_SIZE"):
        WazuhSource()


def test_tls_verification_is_on_by_default(source: WazuhSource) -> None:
    assert source._tls_verify() is True


def test_ca_bundle_is_preferred_over_disabling_verification(
    source: WazuhSource, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_WAZUH_INSECURE", "1")
    monkeypatch.setenv("SECOPS_WAZUH_CA_BUNDLE", "/etc/ssl/certs/wazuh.pem")
    assert source._tls_verify() == "/etc/ssl/certs/wazuh.pem"


def test_disabling_verification_warns_every_run(
    source: WazuhSource, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SECOPS_WAZUH_INSECURE", "1")
    monkeypatch.delenv("SECOPS_WAZUH_CA_BUNDLE", raising=False)
    with caplog.at_level("WARNING"):
        assert source._tls_verify() is False
    assert "TLS verification DISABLED" in caplog.text
