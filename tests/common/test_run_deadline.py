"""A run must end when its time is up, and say where it got to.

THE PROBLEM THIS COVERS. execute() commits each batch inside upsert_many but
writes the watermark once, after the loop. A run killed at TimeoutStartSec has
therefore landed rows and discarded its position, so the next run re-reads the
same window and dies in the same place: rows accumulate, the cursor never moves,
and the only symptom is a FAILED row. Measured on a live warehouse, xdr_alerts
sat at the same watermark for seven days this way.

SIGTERM makes it worse. Python exits without running the except handler, so no
terminal status is written at all and control.ingest_run keeps a RUNNING row
forever -- invisible to anything counting FAILED runs. Sixteen such rows were
cleaned up by hand over two days.

So the guarantee has to be a deadline INSIDE the process, below the unit's cap,
plus a signal handler that turns a stop into a wind-down.

WHY NOT SIMPLY ADVANCE AFTER EVERY BATCH. Records do not arrive in watermark
order uniformly. defectdojo scans DESCENDING, so its first page carries the
highest mark and advancing before the tail is read would skip everything below
it. xdr_endpoints ignores the cursor entirely. A source has to declare that its
fetch order is its watermark order before the framework will trust a partial
run's maximum.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import run as run_mod  # noqa: E402


class _FakeConn:
    def __init__(self) -> None:
        self.rollbacks = 0

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def rollback(self) -> None:
        self.rollbacks += 1


class _Source:
    """Yields marks forever unless stopped, so only a deadline ends the run."""

    name = "wazuh"
    table = "raw_wazuh.alerts"

    def __init__(self, *, ordered: bool, count: int = 10) -> None:
        self.fetch_order_is_watermark_order = ordered
        self.count = count
        self.yielded = 0

    def authenticate(self) -> object:
        return object()

    def fetch(self, creds: object, cursor: str | None) -> Any:
        for i in range(self.count):
            self.yielded += 1
            yield {"mark": f"2026-01-{i + 1:02d}T00:00:00Z"}

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return (record["mark"], None, record["mark"], run_id)

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return record["mark"]


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    conn = _FakeConn()
    calls: dict[str, Any] = {"conn": conn, "landed": [], "watermarks": [],
                             "finished": [], "cursor_in": None}

    def start_run(conn: object, source: str, **kw: Any) -> int:
        return 7

    def upsert_many(conn: object, table: str, rows: Any, **kw: Any) -> int:
        rows = list(rows)
        calls["landed"].append(rows)
        return len(rows)

    def finish_run(conn: object, run_id: int, status: str, read: int,
                   written: int, err: Any = None) -> None:
        calls["finished"].append((status, read, written, err))

    monkeypatch.setattr(run_mod.db, "connect", lambda provider=None: conn)
    monkeypatch.setattr(run_mod.schema_check, "verify_control_schema", lambda conn: None)
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "start_run", start_run)
    monkeypatch.setattr(run_mod.db, "reap_abandoned", lambda *a, **k: 0)
    monkeypatch.setattr(run_mod.db, "get_watermark", lambda conn, name: calls["cursor_in"])
    monkeypatch.setattr(run_mod.db, "upsert_many", upsert_many)
    monkeypatch.setattr(run_mod.db, "set_watermark",
                        lambda conn, src, val: calls["watermarks"].append(val))
    monkeypatch.setattr(run_mod.db, "finish_run", finish_run)
    return calls


def test_a_run_past_its_deadline_stops_pulling_and_lands_what_it_has(
    harness: dict[str, Any],
) -> None:
    """The deadline bounds the RUN, not the query.

    Bounding the span of the query is not the same thing: throughput is ~16
    rows/s, alert volume is bursty, and any single slice above the budget
    repeats the livelock on that slice forever.
    """
    src = _Source(ordered=True, count=10)
    # Expired before the first record, so the stop is unambiguous.
    result = run_mod.execute(src, batch_size=2, deadline_sec=0)

    assert result.status == "SUCCESS"
    assert src.yielded < 10, "it stopped pulling rather than draining the source"
    assert harness["finished"], "and closed its run row"


def test_an_ordered_source_keeps_the_ground_it_covered(
    harness: dict[str, Any],
) -> None:
    """The whole point: a stopped run must not discard its position.

    Without this the next run re-reads the same window and stops in the same
    place. That is the livelock, and it is why xdr_alerts sat at one watermark
    for seven days.
    """
    harness["cursor_in"] = "2026-01-01T00:00:00Z"
    src = _Source(ordered=True, count=10)
    run_mod.execute(src, batch_size=2, deadline_sec=0)

    assert harness["watermarks"], "an ordered source advances on a deadline stop"


def test_an_unordered_source_discards_its_position_on_purpose(
    harness: dict[str, Any],
) -> None:
    """defectdojo scans descending: its first page carries the HIGHEST mark.

    Advancing to the maximum seen so far would skip every record below it that
    the run never reached. Re-reading the window costs time; skipping records
    loses data, so the unordered case keeps today's behaviour.
    """
    harness["cursor_in"] = "2026-01-01T00:00:00Z"
    src = _Source(ordered=False, count=10)
    run_mod.execute(src, batch_size=2, deadline_sec=0)

    assert harness["watermarks"] == [], "an unordered source must not advance"


def test_a_deadline_stop_is_recorded_not_silently_successful(
    harness: dict[str, Any],
) -> None:
    """A partial run that reports a clean SUCCESS is indistinguishable from a
    complete one, and the difference is the thing an operator needs."""
    src = _Source(ordered=True, count=10)
    run_mod.execute(src, batch_size=2, deadline_sec=0)

    status, _read, _written, note = harness["finished"][-1]
    assert status == "SUCCESS"
    assert note and "deadline" in note.lower(), f"note was {note!r}"


def test_a_run_that_finishes_in_time_is_unchanged(harness: dict[str, Any]) -> None:
    """No deadline behaviour on the happy path, including the note."""
    src = _Source(ordered=True, count=4)
    run_mod.execute(src, batch_size=2, deadline_sec=3600)

    assert src.yielded == 4
    assert harness["watermarks"] == ["2026-01-04T00:00:00Z"]
    status, read, written, note = harness["finished"][-1]
    assert (status, read, written) == ("SUCCESS", 4, 4)
    assert not note


def test_a_source_that_declares_nothing_is_treated_as_unordered(
    harness: dict[str, Any],
) -> None:
    """Safe by default: a connector written before this existed must not have
    its position advanced on the strength of an attribute it never set."""
    class _Undeclared(_Source):
        def __init__(self) -> None:
            super().__init__(ordered=False)
            del self.fetch_order_is_watermark_order

    harness["cursor_in"] = "2026-01-01T00:00:00Z"
    run_mod.execute(_Undeclared(), batch_size=2, deadline_sec=0)
    assert harness["watermarks"] == []


def test_sigterm_winds_down_instead_of_killing_the_run(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SIGTERM must become a stop flag, not an exit.

    Unhandled, it kills Python without running the except handler, so no
    terminal status is written and the run row stays RUNNING forever. Sixteen
    such rows were cleaned up by hand over two days.
    """
    installed: dict[str, Any] = {}

    def fake_signal(sig: int, handler: Any) -> Any:
        installed[sig] = handler
        return None

    monkeypatch.setattr(run_mod.signal, "signal", fake_signal)

    import signal as signal_mod

    class _Interrupted(_Source):
        def fetch(self, creds: object, cursor: str | None) -> Any:
            for i in range(10):
                self.yielded += 1
                if i == 2:
                    installed[signal_mod.SIGTERM](signal_mod.SIGTERM, None)
                yield {"mark": f"2026-01-{i + 1:02d}T00:00:00Z"}

    src = _Interrupted(ordered=True)
    result = run_mod.execute(src, batch_size=2, deadline_sec=3600)

    assert signal_mod.SIGTERM in installed, "a handler was installed"
    assert src.yielded < 10, "the run wound down early"
    assert result.status == "SUCCESS"
    status, _r, _w, note = harness["finished"][-1]
    assert status == "SUCCESS" and note, "and said why it stopped"
