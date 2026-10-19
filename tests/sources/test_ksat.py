"""Offline tests for the KnowBe4 KSAT GraphQL connector.

Everything runs against `httpx.MockTransport`; no live network or secret store
is touched. The suite pins the four properties that matter most for KSAT:

1. Field selection stays narrow so queries remain well under the vendor's
   150-line GraphQL complexity cap.
2. Pagination uses the keyset `cursor: BigInt` argument and never `page`.
3. The 310-character JWT bearer token, the endpoint path (`/graphql`), and the
   GraphQL query text never leak into any raised exception or credential repr.
4. Enrollments modified long after `createdAt` (`NOT_STARTED -> IN_PROGRESS ->
   COMPLETED`) are still collected on subsequent runs with a non-null watermark,
   and map to an unchanged `(source_id, _event_time)` upsert key.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest import redaction  # noqa: E402
from secops_ingest.builtin import PACK  # noqa: E402
from secops_ingest.common.watermark import comparable, newer  # noqa: E402
from secops_ingest.packs.registry import resolve_source  # noqa: E402
from secops_ingest.sources import ksat as ksat_mod  # noqa: E402
from secops_ingest.sources.ksat import (  # noqa: E402
    ENROLLMENTS_QUERY,
    PAGE_CAP,
    SOURCE,
    TRAINING_CAMPAIGNS_QUERY,
    KsatCreds,
    KsatError,
    KsatSource,
    normalize_endpoint,
    resolve,
)

#: Synthetic 310-character JWT matching the measured KSAT token length.
FAKE_JWT = (
    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9."
    + "a" * 200
    + "."
    + "b" * 72
)
assert len(FAKE_JWT) == 310


class StubProvider:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.asked: list[str] = []

    def get(self, name: str) -> str:
        self.asked.append(name)
        return self.values[name]


@pytest.fixture(autouse=True)
def _isolate_redaction_registry() -> Iterator[None]:
    saved = set(redaction._REGISTRY)
    redaction._REGISTRY.clear()
    try:
        yield
    finally:
        redaction._REGISTRY.clear()
        redaction._REGISTRY.update(saved)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> StubProvider:
    # Stored value matches Vault: no scheme, path already included.
    stub = StubProvider(
        {
            "ksat.base_url": "training.knowbe4.com/graphql",
            "ksat.api_key": FAKE_JWT,
        }
    )
    monkeypatch.setattr(ksat_mod, "get_provider", lambda: stub)
    return stub


def campaign_node(
    cid: int = 101,
    name: str = "2026 Security Awareness",
    status: str = "IN_PROGRESS",
) -> dict[str, Any]:
    return {
        "id": cid,
        "name": name,
        "status": status,
        "startDate": "2026-10-01T00:00:00Z",
        "endDate": "2026-12-31T23:59:59Z",
        "percentComplete": 65,
    }


def enrollment_node(
    eid: int,
    *,
    status: str = "NOT_STARTED",
    created_at: str = "2026-10-01T09:00:00Z",
    updated_at: str | None = "2026-10-01T09:00:00Z",
    started_at: str | None = None,
    completed_at: str | None = None,
    user_id: int = 501,
) -> dict[str, Any]:
    return {
        "id": eid,
        "status": status,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "startedAt": started_at,
        "completedAt": completed_at,
        "lastStartedAt": started_at,
        "timeSpent": 1200 if completed_at else 0,
        "score": 100 if completed_at else None,
        "policyAcknowledged": bool(completed_at),
        "user": {"id": user_id, "status": "ACTIVE"},
    }


# -- registration and contract ----------------------------------------------


def test_source_exposes_protocol_and_is_registered_in_builtin_pack() -> None:
    assert SOURCE.name == "ksat"
    assert SOURCE.table == "raw_ksat.enrollments"
    assert PACK.sources["ksat"] == "secops_ingest.sources.ksat:SOURCE"
    assert resolve_source("ksat") == "secops_ingest.sources.ksat:SOURCE"


def test_page_size_is_clamped_to_the_api_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_KSAT_PAGE_SIZE", "9999")
    assert KsatSource().page_size == PAGE_CAP


# -- endpoint normalisation and credential safety ---------------------------


_KB4_HOST = "training.knowbe4.com"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("training.knowbe4.com/graphql", f"https://{_KB4_HOST}/graphql"),
        ("training.knowbe4.com/graphql/", f"https://{_KB4_HOST}/graphql"),
        ("training.knowbe4.com", f"https://{_KB4_HOST}/graphql"),
        ("https://ksat.example.com/graphql", "https://ksat.example.com/graphql"),
        ("HTTPS://ksat.example.com/graphql/", "https://ksat.example.com/graphql"),
        ("https://ksat.example.com", "https://ksat.example.com/graphql"),
        ("https://ksat.example.com/", "https://ksat.example.com/graphql"),
    ],
)
def test_normalize_endpoint_handles_schemeless_and_bare_hosts(
    raw: str, expected: str
) -> None:
    endpoint, host = normalize_endpoint(raw)
    assert endpoint == expected
    assert host in expected


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://ksat.example.com/graphql",
        f"http://{_KB4_HOST}/graphql",
        "ftp://ksat.example.com/graphql",
        "",
        "   ",
    ],
)
def test_normalize_endpoint_rejects_non_https_without_leaking_path(
    bad_url: str,
) -> None:
    with pytest.raises(KsatError) as exc_info:
        normalize_endpoint(bad_url)
    assert "/graphql" not in str(exc_info.value)
    assert "knowbe4" not in str(exc_info.value)


def test_resolve_registers_jwt_and_host_for_redaction(
    provider: StubProvider,
) -> None:
    creds = resolve("ksat")
    assert provider.asked == ["ksat.base_url", "ksat.api_key"]
    assert creds.endpoint == f"https://{_KB4_HOST}/graphql"
    assert FAKE_JWT in redaction._REGISTRY
    assert "training.knowbe4.com" in redaction._REGISTRY
    assert FAKE_JWT not in repr(creds)
    assert FAKE_JWT not in str(creds)
    assert "/graphql" not in repr(creds)


# -- complexity limit and field selection -----------------------------------


def test_queries_stay_well_under_the_150_line_complexity_cap(
    provider: StubProvider,
) -> None:
    """KSAT rejects queries exceeding 150 lines; vendor examples run to ~300."""
    sent_queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        query = body["query"]
        sent_queries.append(query)
        if "trainingCampaigns" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [campaign_node(101)],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollments": {
                        "nodes": [enrollment_node(9001)],
                        "pagination": {"cursor": None},
                    }
                }
            },
        )

    source = KsatSource(transport=httpx.MockTransport(handler))
    creds = source.authenticate()
    rows = list(source.fetch(creds, None))
    assert len(rows) == 1
    assert len(sent_queries) == 2

    for query in (TRAINING_CAMPAIGNS_QUERY, ENROLLMENTS_QUERY, *sent_queries):
        lines = [line for line in query.strip().splitlines() if line.strip()]
        assert len(lines) <= 30, f"query has {len(lines)} lines (cap is 150)"
        # Forbidden arguments and PII fields that bloat complexity or leak PII:
        for forbidden in (
            "page",
            "per_page",
            "perPage",
            "dateRangeField",
            "firstName",
            "lastName",
            "email",
            "employeeNumber",
            "phishPronePercentage",
        ):
            assert forbidden not in query, f"forbidden token {forbidden!r} in query"


# -- keyset cursor paging (never page) --------------------------------------


def test_paging_follows_cursor_and_never_sends_page(
    provider: StubProvider,
) -> None:
    campaign_vars: list[dict[str, Any]] = []
    enrollment_vars: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers["Authorization"] == f"Bearer {FAKE_JWT}"
        body = json.loads(request.content.decode())
        query = body["query"]
        variables = body["variables"]
        assert "page" not in variables
        assert "per_page" not in variables

        if "trainingCampaigns" in query:
            campaign_vars.append(variables)
            if variables["cursor"] is None:
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "trainingCampaigns": {
                                "nodes": [campaign_node(101, "Campaign A")],
                                "pagination": {"cursor": 101},
                            }
                        }
                    },
                )
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [campaign_node(202, "Campaign B")],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )

        enrollment_vars.append(variables)
        cid = variables["campaignId"]
        cur = variables["cursor"]
        if cid == 101 and cur is None:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "enrollments": {
                            "nodes": [enrollment_node(1), enrollment_node(2)],
                            "pagination": {"cursor": 1002},
                        }
                    }
                },
            )
        if cid == 101 and cur == 1002:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "enrollments": {
                            "nodes": [enrollment_node(3)],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        if cid == 202 and cur is None:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "enrollments": {
                            "nodes": [enrollment_node(4)],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        raise AssertionError(f"unexpected variables: {variables}")

    source = KsatSource(page_size=2, transport=httpx.MockTransport(handler))
    creds = source.authenticate()
    records = list(source.fetch(creds, None))

    assert [r["id"] for r in records] == [1, 2, 3, 4]
    assert [r["campaign"]["id"] for r in records] == [101, 101, 101, 202]
    assert [v["cursor"] for v in campaign_vars] == [None, 101]
    assert [(v["campaignId"], v["cursor"], v["per"]) for v in enrollment_vars] == [
        (101, None, 2),
        (101, 1002, 2),
        (202, None, 2),
    ]


# -- re-reading captures post-creation mutations ----------------------------


def test_record_modified_after_creation_is_collected_and_upserts_in_place(
    provider: StubProvider,
) -> None:
    """The whole point of re-reading rather than tailing CREATED_AT.

    Enrollment 9001 is created on Oct 1 (`NOT_STARTED`). Another enrollment 9002
    advances the run 1 watermark to Oct 10. On Oct 15, enrollment 9001 transitions
    to `COMPLETED`. Run 2 is invoked with `cursor = "2026-10-10T12:00:00Z"`.

    A `CREATED_AT` filter would skip 9001 forever because `2026-10-01 < 2026-10-10`.
    Re-reading collects 9001 with its new `COMPLETED` state, preserves its
    `(source_id, _event_time)` primary key so the warehouse upsert overwrites the
    existing row rather than duplicating it, and advances the watermark to the
    Oct 15 mutation timestamp.
    """
    run_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if "trainingCampaigns" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [campaign_node(101)],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        if run_number == 1:
            nodes = [
                enrollment_node(
                    9001,
                    status="NOT_STARTED",
                    created_at="2026-10-01T09:00:00Z",
                    updated_at="2026-10-01T09:00:00Z",
                ),
                enrollment_node(
                    9002,
                    status="IN_PROGRESS",
                    created_at="2026-10-10T11:00:00Z",
                    updated_at="2026-10-10T12:00:00Z",
                    started_at="2026-10-10T12:00:00Z",
                ),
            ]
        else:
            nodes = [
                enrollment_node(
                    9001,
                    status="COMPLETED",
                    created_at="2026-10-01T09:00:00Z",
                    updated_at="2026-10-15T16:45:00Z",
                    started_at="2026-10-15T16:15:00Z",
                    completed_at="2026-10-15T16:45:00Z",
                ),
                enrollment_node(
                    9002,
                    status="IN_PROGRESS",
                    created_at="2026-10-10T11:00:00Z",
                    updated_at="2026-10-10T12:00:00Z",
                    started_at="2026-10-10T12:00:00Z",
                ),
            ]
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollments": {
                        "nodes": nodes,
                        "pagination": {"cursor": None},
                    }
                }
            },
        )

    source = KsatSource(transport=httpx.MockTransport(handler))
    creds = source.authenticate()

    # Run 1: initial read with no cursor.
    run_number = 1
    run1_records = list(source.fetch(creds, None))
    run1_rows = {r["id"]: source.to_row(r, 1) for r in run1_records}
    watermark_1: Any = None
    for r in run1_records:
        mark = source.watermark_of(r)
        if newer(mark, watermark_1):
            watermark_1 = mark
    assert watermark_1 == "2026-10-10T12:00:00Z"

    # Run 2: invoked with Run 1's watermark; 9001 was created 9 days before cursor.
    run_number = 2
    run2_records = list(source.fetch(creds, str(watermark_1)))
    by_id = {r["id"]: r for r in run2_records}
    assert by_id[9001]["status"] == "COMPLETED"
    assert by_id[9001]["completedAt"] == "2026-10-15T16:45:00Z"

    run2_rows = {r["id"]: source.to_row(r, 2) for r in run2_records}
    # Upsert key (source_id, _event_time) must not move when the enrollment mutates.
    assert (run1_rows[9001][0], run1_rows[9001][2]) == (
        run2_rows[9001][0],
        run2_rows[9001][2],
    ) == ("9001", "2026-10-01T09:00:00Z")

    watermark_2 = watermark_1
    for r in run2_records:
        mark = source.watermark_of(r)
        if newer(mark, watermark_2):
            watermark_2 = mark
    assert watermark_2 == "2026-10-15T16:45:00Z"
    assert isinstance(comparable(watermark_2), datetime)


def test_watermark_falls_back_to_created_at_when_updated_at_is_null() -> None:
    source = KsatSource()
    rec = enrollment_node(1, created_at="2026-10-01T09:00:00Z", updated_at=None)
    assert source.watermark_of(rec) == "2026-10-01T09:00:00Z"


def test_to_row_maps_zero_run_id_to_none_for_dry_run() -> None:
    source = KsatSource()
    rec = enrollment_node(42, created_at="2026-10-01T09:00:00Z")
    sid, payload, event_time, run_id = source.to_row(rec, 0)
    assert sid == "42"
    assert json.loads(payload)["id"] == 42
    assert event_time == "2026-10-01T09:00:00Z"
    assert run_id is None


def test_campaign_and_enrollment_status_scoping(
    provider: StubProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_KSAT_CAMPAIGN_STATUS", "IN_PROGRESS")
    monkeypatch.setenv("SECOPS_KSAT_ENROLLMENT_STATUS", "COMPLETED")
    seen_vars: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        seen_vars.append(body["variables"])
        if "trainingCampaigns" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [campaign_node(101, status="IN_PROGRESS")],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollments": {
                        "nodes": [enrollment_node(9001, status="COMPLETED")],
                        "pagination": {"cursor": None},
                    }
                }
            },
        )

    source = KsatSource(transport=httpx.MockTransport(handler))
    creds = source.authenticate()
    got = list(source.fetch(creds, None))
    assert len(got) == 1
    assert seen_vars[0]["status"] == "IN_PROGRESS"
    assert seen_vars[1]["campaignId"] == 101
    assert seen_vars[1]["status"] == "COMPLETED"


# -- error hygiene: never leak token, endpoint path, or query text ----------


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500, 503])
def test_http_errors_never_leak_token_endpoint_path_or_query_text(
    provider: StubProvider, status_code: int
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Deliberately echo the token, endpoint path, and query in the error body.
        return httpx.Response(
            status_code,
            text=f"error at {request.url} for {FAKE_JWT} running {TRAINING_CAMPAIGNS_QUERY}",
        )

    source = KsatSource(
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        attempts=2,
    )
    creds = source.authenticate()
    with pytest.raises(Exception) as exc_info:
        list(source.fetch(creds, None))

    rendered = (
        f"{exc_info.value!s}\n{exc_info.value!r}\n"
        + "".join(traceback.format_exception(exc_info.value))
    )
    assert FAKE_JWT not in rendered
    assert "/graphql" not in rendered
    assert "training.knowbe4.com" not in rendered
    assert "trainingCampaigns" not in rendered
    assert "percentComplete" not in rendered


def test_graphql_errors_never_leak_token_endpoint_path_or_query_text(
    provider: StubProvider,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "errors": [
                    {
                        "message": (
                            f"Complexity 300 > 150 at /graphql with {FAKE_JWT}: "
                            f"{TRAINING_CAMPAIGNS_QUERY}"
                        )
                    }
                ]
            },
        )

    source = KsatSource(transport=httpx.MockTransport(handler))
    creds = source.authenticate()
    with pytest.raises(KsatError) as exc_info:
        list(source.fetch(creds, None))

    rendered = (
        f"{exc_info.value!s}\n{exc_info.value!r}\n"
        + "".join(traceback.format_exception(exc_info.value))
    )
    assert FAKE_JWT not in rendered
    assert "/graphql" not in rendered
    assert "trainingCampaigns" not in rendered


def test_transport_errors_never_leak_token_endpoint_path_or_query_text(
    provider: StubProvider,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            f"connect failed to {request.url} auth={FAKE_JWT} query={TRAINING_CAMPAIGNS_QUERY}",
            request=request,
        )

    source = KsatSource(
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        attempts=2,
    )
    creds = source.authenticate()
    with pytest.raises(KsatError) as exc_info:
        list(source.fetch(creds, None))

    rendered = (
        f"{exc_info.value!s}\n{exc_info.value!r}\n"
        + "".join(traceback.format_exception(exc_info.value))
    )
    assert FAKE_JWT not in rendered
    assert "/graphql" not in rendered
    assert "training.knowbe4.com" not in rendered
    assert "trainingCampaigns" not in rendered


def test_transient_503_retries_and_succeeds(provider: StubProvider) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, headers={"Retry-After": "0"})
        body = json.loads(request.content.decode())
        if "trainingCampaigns" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [campaign_node(101)],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollments": {
                        "nodes": [enrollment_node(9001)],
                        "pagination": {"cursor": None},
                    }
                }
            },
        )

    source = KsatSource(
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )
    creds = source.authenticate()
    got = list(source.fetch(creds, None))
    assert [r["id"] for r in got] == [9001]
    assert calls == 3


def test_empty_api_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = StubProvider({"ksat.base_url": "ksat.example.com/graphql", "ksat.api_key": "   "})
    monkeypatch.setattr(ksat_mod, "get_provider", lambda: stub)
    with pytest.raises(KsatError, match="api_key"):
        resolve("ksat")


def test_normalize_endpoint_handles_subpath_and_missing_host() -> None:
    endpoint, host = normalize_endpoint("https://ksat.example.com/api/v1")
    assert endpoint == "https://ksat.example.com/api/v1/graphql"
    assert host == "ksat.example.com"
    with pytest.raises(KsatError, match="https://"):
        normalize_endpoint("http:ksat.example.com")
    with pytest.raises(KsatError, match="no host"):
        normalize_endpoint("https:///graphql")


def test_authenticate_accepts_explicit_creds_and_fetch_auto_authenticates(
    provider: StubProvider,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"trainingCampaigns": {"nodes": [], "pagination": {"cursor": None}}}},
        )

    source = KsatSource(transport=httpx.MockTransport(handler))
    explicit = KsatCreds(api_key=FAKE_JWT, endpoint="https://ksat.example.com/graphql")
    assert source.authenticate(explicit) == explicit
    assert FAKE_JWT in redaction._REGISTRY

    source2 = KsatSource(transport=httpx.MockTransport(handler))
    assert list(source2.fetch(None, None)) == []


def test_repeated_cursor_terminates_without_infinite_loop(
    provider: StubProvider,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if "trainingCampaigns" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "trainingCampaigns": {
                            "nodes": [
                                campaign_node(101, status="IN_PROGRESS"),
                                campaign_node(102, status="CLOSED"),
                            ],
                            "pagination": {"cursor": None},
                        }
                    }
                },
            )
        # Server bug: returns the same cursor (555) on every page.
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollments": {
                        "nodes": [enrollment_node(9001)],
                        "pagination": {"cursor": 555},
                    }
                }
            },
        )

    source = KsatSource(
        campaign_status="IN_PROGRESS",
        transport=httpx.MockTransport(handler),
    )
    records = list(source.fetch(source.authenticate(), None))
    assert [r["id"] for r in records] == [9001, 9001]


def test_malformed_json_and_missing_data_raise_clean_ksat_error(
    provider: StubProvider,
) -> None:
    responses: list[httpx.Response] = [
        httpx.Response(200, text=f"not-json {FAKE_JWT}"),
        httpx.Response(200, json=[1, 2, 3]),
        httpx.Response(200, json={"data": None}),
        httpx.Response(200, json={"data": {"trainingCampaigns": "bad"}}),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    source = KsatSource(transport=httpx.MockTransport(handler))
    creds = source.authenticate()
    for _ in range(4):
        with pytest.raises(KsatError) as exc_info:
            list(source.fetch(creds, None))
        assert FAKE_JWT not in str(exc_info.value)


def test_timeout_and_http_error_raise_clean_ksat_error(
    provider: StubProvider,
) -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timeout {FAKE_JWT} at {request.url}", request=request)

    source = KsatSource(
        transport=httpx.MockTransport(timeout_handler),
        sleep=lambda _: None,
        attempts=2,
    )
    with pytest.raises(KsatError) as exc_info:
        list(source.fetch(source.authenticate(), None))
    assert FAKE_JWT not in str(exc_info.value)
    assert "/graphql" not in str(exc_info.value)

    def generic_http_error(request: httpx.Request) -> httpx.Response:
        raise httpx.HTTPError(f"generic {FAKE_JWT} at {request.url}")

    source2 = KsatSource(
        transport=httpx.MockTransport(generic_http_error),
        sleep=lambda _: None,
        attempts=1,
    )
    with pytest.raises(KsatError) as exc_info2:
        list(source2.fetch(source2.authenticate(), None))
    assert FAKE_JWT not in str(exc_info2.value)
    assert "/graphql" not in str(exc_info2.value)

