"""A transform run must end when its time is up, and say where it got to.

THE PROBLEM THIS COVERS. The transform never got common/run.py's deadline or
its SIGTERM handler. Killed at the unit's TimeoutStartSec it wrote no outcome,
so control.transform_run kept a RUNNING row forever. And its upsert was one
statement under a 900s role statement_timeout: a backlog bigger than that was
cancelled by the server, the watermark did not move, and the identical
statement was cancelled again on every later run.

So a backlog is applied in chunks, each committed with its watermark, and the
deadline and SIGTERM are checked between chunks. These tests drive that loop
with a fake connection; tests/transform/test_transform_integration.py drives
it through real SQL.
"""

from __future__ import annotations

import signal
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.transform import runner  # noqa: E402
from secops_ingest.transform.base import Target  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=UTC)
BOUNDS = [T0 + timedelta(minutes=m) for m in (10, 20, 30, 40)]
RAW_MARK = BOUNDS[-1]


def make(*, chunkable: bool = True) -> Target:
    where = "WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz"
    if chunkable:
        where += " AND _ingested_at <= %(until)s::timestamptz"
    return Target(
        name="t",
        raw_table="raw_x.things",
        fact_table="mart_fact_t",
        fact_date_expr="created_at",
        upsert_sql=f"INSERT INTO mart_fact_t SELECT 1 FROM raw_x.things {where}",
    )


class _FakeConn:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0
        self.cancels = 0

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def cancel_safe(self) -> None:
        self.cancels += 1


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    conn = _FakeConn()
    calls: dict[str, Any] = {
        "conn": conn, "started": 0, "finished": [], "advanced": [], "chunks": [],
        "unlocked": 0, "lock_free": True, "disabled": None, "watermark": None,
        "on_chunk": None,
    }

    def start(conn: object, target: str, posture: object) -> int:
        calls["started"] += 1
        return 11

    def finish(conn: object, run_id: int, status: str, rows: int, days: int,
               error: str | None) -> None:
        calls["finished"].append((status, rows, days, error))

    def advance(conn: object, target: str, value: Any) -> None:
        calls["advanced"].append(value)
        calls["watermark"] = value

    def next_bound(conn: object, target: Target, lo: Any, hi: Any, n: int) -> Any:
        later = [b for b in BOUNDS if lo is None or b > lo]
        return later[0] if later else hi

    def apply_chunk(conn: object, target: Target, since: Any, until: Any) -> Any:
        calls["chunks"].append((since, until))
        if calls["on_chunk"]:
            calls["on_chunk"](len(calls["chunks"]))
        return 5, [T0.date()]

    def unlock(conn: object, target: str) -> None:
        calls["unlocked"] += 1

    monkeypatch.setattr(runner.db, "connect", lambda: conn)
    monkeypatch.setattr(runner, "verify_control_schema", lambda conn: None)
    # raising=False: the target check lands on fix/audit-schema; stubbed like
    # the control check either way, since a fake connection has no catalog.
    monkeypatch.setattr(runner.schema_check, "verify_target_schema",
                        lambda conn, targets: None, raising=False)
    monkeypatch.setattr(runner, "try_lock_target", lambda conn, t: calls["lock_free"])
    monkeypatch.setattr(runner, "unlock_target", unlock)
    monkeypatch.setattr(runner, "_disabled_owner", lambda conn, t: calls["disabled"])
    monkeypatch.setattr(runner, "_reap_abandoned", lambda conn, t, age: [])
    monkeypatch.setattr(runner, "_start", start)
    monkeypatch.setattr(runner, "_finish", finish)
    monkeypatch.setattr(runner, "_watermark", lambda conn, t: calls["watermark"])
    monkeypatch.setattr(runner, "_advance", advance)
    monkeypatch.setattr(runner, "_raw_mark", lambda conn, t: (RAW_MARK, timedelta(minutes=5)))
    monkeypatch.setattr(runner, "_next_bound", next_bound)
    monkeypatch.setattr(runner, "_apply_chunk", apply_chunk)
    return calls


def test_a_backlog_is_applied_in_chunks_each_advancing_the_watermark(
    harness: dict[str, Any],
) -> None:
    """The watermark moves once per chunk, to that chunk's top, in order.

    One advance at the end is the livelock: a run cancelled before it keeps
    nothing, and the next run starts the same statement from the same place.
    """
    result = runner.execute(make())

    assert result.status == "SUCCESS"
    assert harness["chunks"] == [(None, BOUNDS[0]), (BOUNDS[0], BOUNDS[1]),
                                 (BOUNDS[1], BOUNDS[2]), (BOUNDS[2], BOUNDS[3])]
    assert harness["advanced"] == BOUNDS
    assert result.rows_upserted == 20
    assert harness["finished"] == [("SUCCESS", 20, 1, None)]


def test_a_run_past_its_deadline_starts_no_chunk_and_records_failed(
    harness: dict[str, Any],
) -> None:
    result = runner.execute(make(), deadline_sec=0)

    assert result.status == "FAILED"
    assert harness["chunks"] == []
    assert harness["advanced"] == []
    status, rows, _, why = harness["finished"][0]
    assert (status, rows) == ("FAILED", 0)
    assert "stopped at the 0s deadline after 0 chunk(s)" in why


def test_sigterm_between_chunks_keeps_the_finished_chunks_and_records_failed(
    harness: dict[str, Any],
) -> None:
    """A systemd stop is a wind-down: the row says FAILED and how far it got,
    instead of staying RUNNING forever after the SIGKILL that would follow."""

    def term_after_second(n: int) -> None:
        if n == 2:
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler), "no SIGTERM handler installed during the run"
            handler(signal.SIGTERM, None)

    harness["on_chunk"] = term_after_second
    result = runner.execute(make())

    assert result.status == "FAILED"
    assert len(harness["chunks"]) == 2
    assert harness["advanced"] == BOUNDS[:2]
    status, rows, _, why = harness["finished"][0]
    assert (status, rows) == ("FAILED", 10)
    assert "stopped at SIGTERM after 2 chunk(s)" in why
    assert f"watermark at {BOUNDS[1]}" in why
    # Signalled while the chunk was in flight, so its statement was cancelled
    # rather than left to run into systemd's SIGKILL.
    assert harness["conn"].cancels == 1


def test_sigterm_cancelling_a_chunk_is_recorded_as_a_stop(
    harness: dict[str, Any],
) -> None:
    class QueryCanceled(Exception):
        pass

    def cancelled_third(n: int) -> None:
        if n == 3:
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)  # type: ignore[operator]
            raise QueryCanceled("canceling statement due to user request")

    harness["on_chunk"] = cancelled_third
    with pytest.raises(QueryCanceled):
        runner.execute(make())

    assert harness["advanced"] == BOUNDS[:2], "the cancelled chunk must not advance"
    status, rows, _, why = harness["finished"][0]
    assert (status, rows) == ("FAILED", 10)
    assert why.startswith("stopped at SIGTERM during a chunk; QueryCanceled")
    assert "after 2 committed chunk(s)" in why


def test_the_previous_sigterm_handler_is_restored(harness: dict[str, Any]) -> None:
    before = signal.getsignal(signal.SIGTERM)
    runner.execute(make())
    assert signal.getsignal(signal.SIGTERM) is before


def test_a_locked_target_writes_nothing(harness: dict[str, Any]) -> None:
    """Another run, or `packs drop`, holds the target: no ledger row at all."""
    harness["lock_free"] = False

    result = runner.execute(make())

    assert result.status == "BUSY"
    assert harness["started"] == 0
    assert harness["unlocked"] == 0, "must not release a lock it does not hold"


def test_a_disabled_pack_writes_nothing_and_releases_the_lock(
    harness: dict[str, Any],
) -> None:
    harness["disabled"] = "builtin"

    result = runner.execute(make())

    assert result.status == "DISABLED"
    assert harness["started"] == 0
    assert harness["chunks"] == []
    assert harness["unlocked"] == 1


def test_stale_raw_says_why_it_moved_nothing(harness: dict[str, Any]) -> None:
    """SUCCESS with 0 rows must not read the same for "quiet" and "stopped"."""
    harness["watermark"] = RAW_MARK

    result = runner.execute(make())

    assert result.status == "SUCCESS"
    assert harness["chunks"] == []
    status, rows, _, why = harness["finished"][0]
    assert (status, rows) == ("SUCCESS", 0)
    assert why.startswith("nothing new: raw_x.things last received rows at")
    assert "(0:05:00 ago)" in why


def test_a_target_without_until_runs_as_one_statement_and_says_so(
    harness: dict[str, Any],
) -> None:
    """A pack written before %(until)s keeps working, and the ledger names the
    exposure instead of hiding it."""
    result = runner.execute(make(chunkable=False))

    assert result.status == "SUCCESS"
    assert harness["chunks"] == [(None, None)]
    assert harness["advanced"] == [RAW_MARK]
    assert "applied as one statement" in (result.note or "")
    assert harness["finished"][0][3] == result.note


def test_target_schema_drift_refuses_before_any_ledger_row(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """V-32: a mart behind the package is refused before the lock and before
    _start, so a refused run leaves no RUNNING row -- as the control check."""
    from secops_ingest.common import schema_check

    class Drift(RuntimeError):
        pass

    seen: list[list[str]] = []

    def check(conn: object, targets: list[Target]) -> None:
        seen.append([t.name for t in targets])
        raise Drift("mart_fact_t is missing column(s): x")

    monkeypatch.setattr(schema_check, "verify_target_schema", check, raising=False)
    taken: list[str] = []
    monkeypatch.setattr(runner, "try_lock_target", lambda conn, t: taken.append(t) or True)

    with pytest.raises(Drift):
        runner.execute(make())

    assert seen == [["t"]]
    assert taken == []
    assert harness["started"] == 0


def test_without_the_target_check_the_run_proceeds(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Merge window: on a tree without verify_target_schema, nothing changes."""
    from secops_ingest.common import schema_check

    monkeypatch.delattr(schema_check, "verify_target_schema", raising=False)

    assert runner.execute(make()).status == "SUCCESS"
