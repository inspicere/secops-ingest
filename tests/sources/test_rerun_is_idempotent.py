"""The spec's one universal case: a second run over the same records is a no-op.

Every connector here relies on it. The framework advances the watermark only
after a successful land, so a crash mid-run guarantees an overlap on the next
one; wazuh, xdr_alerts and xdr all deliberately re-read a trailing window on top
of that. All of it is safe only because landing is an upsert keyed on
(source_id, _event_time) and that key is a pure function of the record.

So this asserts the key, not the row. The payload is expected to change between
runs -- that is what an upsert is for. What must NOT change is which row the
second run writes over: a key that moves turns every overlap into a duplicate
insert, and the table grows a little every time a run is retried.

Tested per connector rather than once, because each derives the key from a
different field and the mistake is per connector: reaching for the mutable
field the watermark uses instead of the immutable creation field.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.sources import _cortex

CREDS = _cortex.CortexCreds(key="k" * 32, key_id="1",
                           base="https://api-tenant.example.com/p")

#: The snapshot connector pins one timestamp per run BY DESIGN -- that is what
#: makes policy drift a time series instead of a current-state table. So its key
#: is a function of (record, run instant), and the run instant is frozen here to
#: hold the one variable this test is not about.
FROZEN = "2026-09-14T00:00:00+00:00"


def xsoar_records() -> list[dict[str, Any]]:
    return [{"id": str(i), "created": f"2026-01-0{i}T00:00:00.000Z",
             "modified": f"2026-09-0{i}T00:00:00.000Z", "status": 2,
             "severity": 3, "owner": "analyst", "type": "synthetic type",
             "sourceBrand": "Cortex XDR - IR", "dbotMirrorId": f"xdr-{i}",
             "openDuration": 120} for i in (1, 2, 3)]


def xdr_records() -> list[dict[str, Any]]:
    return [{"incident_id": str(i), "creation_time": 1_789_000_000_000 + i,
             "modification_time": 1_789_900_000_000 + i, "status": "new",
             "severity": "high", "alert_count": i} for i in (1, 2, 3)]


def alert_records() -> list[dict[str, Any]]:
    return [{"alert_id": str(i), "detection_timestamp": 1_789_000_000_000 + i,
             "local_insert_ts": 1_789_000_500_000 + i, "severity": "high",
             "category": "Malware", "source": "XDR Agent",
             "name": "synthetic", "resolution_status": "STATUS_010_NEW"}
            for i in (1, 2, 3)]


def endpoint_records() -> list[dict[str, Any]]:
    return [{"endpoint_id": str(i), "endpoint_name": "host",
             "endpoint_status": "CONNECTED", "agent_version": "8.4.0.1",
             "content_version": "1000-1000", "os_type": "AGENT_OS_WINDOWS",
             "last_seen": 1_789_400_000_000, "is_isolated": "AGENT_UNISOLATED",
             "operational_status": "PROTECTED",
             "assigned_prevention_policy": "Windows Servers",
             "assigned_extensions_policy": "Default"} for i in (1, 2, 3)]


def reply_xsoar(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"total": 3, "data": rows}


def reply_under(key: str) -> Any:
    def build(rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {"reply": {"total_count": 3, "result_count": len(rows), key: rows}}
    return build


CONNECTORS = {
    "xsoar": ("SECOPS_XSOAR_PAGE_SIZE", xsoar_records, reply_xsoar),
    "xdr": ("SECOPS_XDR_PAGE_SIZE", xdr_records, reply_under("incidents")),
    "xdr_alerts": ("SECOPS_XDR_ALERTS_PAGE_SIZE", alert_records,
                   reply_under("alerts")),
    "xdr_endpoints": ("SECOPS_XDR_ENDPOINTS_PAGE_SIZE", endpoint_records,
                      reply_under("endpoints")),
}


def build(name: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The connector's SOURCE, with credentials stubbed and paging set to 2.

    Two pages of a three-record collection, so the rerun crosses a page boundary
    rather than fitting in one request.
    """
    import importlib

    page_env, _records, _reply = CONNECTORS[name]
    monkeypatch.setenv(page_env, "2")
    module = importlib.import_module(f"secops_ingest.sources.{name}")
    monkeypatch.setattr(module, "resolve", lambda secret, path: CREDS)
    source = type(module.SOURCE)()
    source._creds = CREDS
    if name == "xdr_endpoints":
        source._snapshot_at = lambda: FROZEN
    return source


def keys_from_one_run(source: Any, records: list[dict[str, Any]],
                      reply: Any) -> list[tuple[Any, Any]]:
    """Drive fetch() over a fresh copy of the same pages and return the keys."""
    pages = [records[:2], records[2:]]

    def post(creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        return reply(pages.pop(0) if pages else [])

    source._post = post
    rows = [source.to_row(record, 1) for record in source.fetch({}, None)]
    assert not pages, "the stub was not paged to exhaustion"
    # (source_id, _event_time) -- positions 0 and 2 of the landing tuple.
    return [(row[0], row[2]) for row in rows]


@pytest.mark.parametrize("name", sorted(CONNECTORS))
def test_a_second_run_over_the_same_records_writes_no_new_rows(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("httpx", reason="needs the 'http' extra")
    _page_env, records, reply = CONNECTORS[name]

    first = keys_from_one_run(build(name, monkeypatch), records(), reply)
    second = keys_from_one_run(build(name, monkeypatch), records(), reply)

    assert len(first) == 3, f"{name} did not read all three records"
    assert len(set(first)) == 3, f"{name} produced a colliding upsert key"
    assert first == second, (
        f"{name}: the upsert key moved between two runs over identical "
        f"records, so every re-read inserts instead of updating")


@pytest.mark.parametrize("name", sorted(CONNECTORS))
def test_the_upsert_key_ignores_whatever_changed_since_the_last_run(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second run sees the same records with their mutable fields moved on.

    This is the realistic shape of a re-read: an incident was touched, an alert
    was triaged, an endpoint checked in again. The key must not follow, or the
    row lands in a second partition and the first copy is stranded there
    forever.
    """
    pytest.importorskip("httpx", reason="needs the 'http' extra")
    _page_env, records, reply = CONNECTORS[name]

    original = records()
    touched = records()
    for record in touched:
        for field in ("modified", "modification_time", "local_insert_ts",
                      "last_seen"):
            if field in record:
                record[field] = (record[field] + 1 if isinstance(record[field], int)
                                 else "2026-12-31T00:00:00.000Z")
        for field in ("status", "resolution_status", "endpoint_status"):
            if field in record:
                record[field] = "CHANGED" if isinstance(record[field], str) else 3

    first = keys_from_one_run(build(name, monkeypatch), original, reply)
    second = keys_from_one_run(build(name, monkeypatch), touched, reply)
    assert first == second, f"{name}: the upsert key tracks a mutable field"
