"""The KSAT phishing-runs source, against measured API behaviour.

EVERY NAME AND SHAPE HERE WAS MEASURED against training.knowbe4.com/graphql on
2026-10-20, before any connector code existed. The training source was written
from notes instead, and its first live call returned six GraphQL errors while
34 mock tests passed -- because the mocks shared the notes' misunderstanding.

What the measurements established, and what each one costs if assumed wrong:

  * 117 runs exist, across 19 campaigns. `pages` is reported; `page` paging
    walks all 117, and `cursor` paging reaches 25 and reports success.
  * phishPronePercentage is a FRACTION, not a percent, and not round:
    0.0078003120124804995 was observed. An integer column stores 0.
  * startedAt is null on a run whose status is ERROR; completedAt is set.
  * campaign.campaignType is a real field ("standard"); campaign.name is PII-free.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.packs.registry import resolve_source  # noqa: E402
from secops_ingest.sources import _ksat as _ksat_mod  # noqa: E402
from secops_ingest.sources.ksat_phishing_runs import (  # noqa: E402
    PHISHING_RUNS_QUERY,
    SOURCE,
    KsatPhishingRunsSource,
)

FAKE_JWT = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." + "a" * 262


class StubProvider:
    def get(self, name: str) -> str:
        return {
            "ksat.base_url": "training.knowbe4.com/graphql",
            "ksat.api_key": FAKE_JWT,
        }[name]


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> StubProvider:
    stub = StubProvider()
    monkeypatch.setattr(_ksat_mod, "get_provider", lambda: stub)
    return stub


def run_node(run_id: int, **over: Any) -> dict[str, Any]:
    """A run as the API actually returns one. Values are measured."""
    node = {
        "id": str(run_id),
        "status": "CLOSED",
        "createdAt": "2026-10-06T13:58:00Z",
        "startedAt": "2026-10-06T14:00:13Z",
        "completedAt": "2026-10-18T14:00:13Z",
        "duration": 12,
        "recipientCount": 641,
        "scheduledCount": 641,
        # measured: a fraction, and not round
        "phishPronePercentage": 0.0078003120124804995,
        "reportedPercentage": 0.6396255850234009,
        "campaign": {"id": "771", "name": "Q4 Simulation", "campaignType": "standard"},
    }
    node.update(over)
    return node


def _handler(total: int, per: int, *, seen: list[dict[str, Any]]) -> Any:
    pages = max(1, (total + per - 1) // per)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        seen.append(dict(body["variables"]))
        page = body["variables"]["page"]
        start = (page - 1) * per
        ids = range(start, min(start + per, total))
        return httpx.Response(
            200,
            json={
                "data": {
                    "phishingCampaignRuns": {
                        "nodes": [run_node(18000000 + i) for i in ids],
                        "pagination": {
                            "page": page, "pages": pages,
                            "per": per, "totalCount": total,
                        },
                    }
                }
            },
        )

    return handler


def test_source_exposes_the_protocol_and_resolves_by_bare_name() -> None:
    assert resolve_source("ksat_phishing_runs") == (
        "secops_ingest.sources.ksat_phishing_runs:SOURCE"
    )
    assert SOURCE.name == "ksat_phishing_runs"
    assert SOURCE.table == "raw_ksat.phishing_runs"
    for method in ("authenticate", "fetch", "to_row", "watermark_of"):
        assert hasattr(SOURCE, method), method


def test_query_names_only_fields_the_schema_has() -> None:
    for field in (
        "status", "createdAt", "startedAt", "completedAt",
        "recipientCount", "scheduledCount",
        "phishPronePercentage", "reportedPercentage",
    ):
        assert field in PHISHING_RUNS_QUERY, f"missing {field}"
    # measured: the argument is campaignId on runs, and sorting is started_at
    assert "sortField: started_at" in PHISHING_RUNS_QUERY
    # cursor is accepted by the API and never populates nextCursor
    assert "cursor" not in PHISHING_RUNS_QUERY
    assert "nextCursor" not in PHISHING_RUNS_QUERY


def test_query_declares_what_it_sends_and_selects_what_the_walker_reads(
    provider: StubProvider,
) -> None:
    """The two bugs mocks cannot see, guarded up front this time."""
    seen: list[dict[str, Any]] = []
    source = KsatPhishingRunsSource(transport=httpx.MockTransport(
        _handler(1, 50, seen=seen)), page_size=50)
    list(source.fetch(source.authenticate(), None))
    for name in seen[0]:
        assert f"${name}" in PHISHING_RUNS_QUERY, f"sends {name}, never declares it"
    block = PHISHING_RUNS_QUERY.split("pagination {")[1].split("}")[0]
    for field in ("pages", "totalCount"):
        assert field in block, f"walker reads pagination.{field}, query omits it"


def test_every_page_is_walked(provider: StubProvider) -> None:
    """117 runs at per=50 is three pages; cursor paging reached one."""
    seen: list[dict[str, Any]] = []
    source = KsatPhishingRunsSource(
        transport=httpx.MockTransport(_handler(117, 50, seen=seen)), page_size=50
    )
    got = list(source.fetch(source.authenticate(), None))
    assert [v["page"] for v in seen] == [1, 2, 3], seen
    assert len(got) == 117
    assert len({r["id"] for r in got}) == 117, "duplicate runs yielded"


def test_event_time_is_createdAt_which_does_not_move(provider: StubProvider) -> None:
    """A run's aggregates change as recipients act; createdAt does not.

    Keying on it means a re-read refreshes the row in place rather than
    inserting a second one under a new partition.
    """
    source = KsatPhishingRunsSource(transport=httpx.MockTransport(
        _handler(1, 50, seen=[])), page_size=50)
    record = next(iter(source.fetch(source.authenticate(), None)))
    source_id, payload, event_time, run = source.to_row(record, 7)
    assert source_id == record["id"]
    assert event_time == record["createdAt"]
    assert run == 7
    assert json.loads(payload)["phishPronePercentage"] == pytest.approx(0.0078003120124805)


def test_watermark_prefers_the_latest_time_the_run_actually_has(
    provider: StubProvider,
) -> None:
    """An ERRORed run has completedAt but no startedAt -- measured, run 18223589."""
    source = KsatPhishingRunsSource(transport=httpx.MockTransport(
        _handler(1, 50, seen=[])), page_size=50)
    assert source.watermark_of(run_node(1)) == "2026-10-18T14:00:13Z"
    errored = run_node(2, status="ERROR", startedAt=None,
                       completedAt="2026-09-06T19:08:27Z")
    assert source.watermark_of(errored) == "2026-09-06T19:08:27Z"
    never = run_node(3, startedAt=None, completedAt=None)
    assert source.watermark_of(never) == never["createdAt"]
