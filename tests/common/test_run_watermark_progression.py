"""How `execute()` moves the cursor -- and where it does not.

WHY THIS FILE EXISTS. `tests/common/test_watermark_ordering.py` covers
`common.watermark.newer` and `comparable`: given two marks, which is later.
Those helpers are well tested. What was not tested anywhere is the thing built
on top of them -- whether a RUN leaves the cursor somewhere sensible. The
idempotency tests assert the upsert key, not cursor progression, so a change to
the ordering of `set_watermark` against the batch loop could not fail any test.

That matters because the design's §4 termination work rewrites exactly that
ordering. Rewriting untested code is how a livelock becomes two livelocks.

SEVERAL TESTS HERE ASSERT BEHAVIOUR THAT IS WRONG. They are marked LIVELOCK in
their names and say so in their docstrings. They are characterisation tests:
they pin down what today's code does so that the fix has to change them
deliberately, in the same commit, where a reviewer can see the before and after.
A test that merely described the intended future would pass vacuously today and
prove nothing about either state.

NO DATABASE IS INVOLVED. Every `db` function is monkeypatched, so these run
offline and in milliseconds. They still need the `postgres` extra, because
`common.run` reaches psycopg through `common.db` at import time.
"""

from __future__ import annotations

from typing import Any

import pytest

# Needs the 'postgres' extra: common.run reaches psycopg through common.db.
pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import run as run_mod  # noqa: E402


class _FakeConn:
    """Stands in for a psycopg connection, and counts rollbacks."""

    def __init__(self) -> None:
        self.rollbacks = 0

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def rollback(self) -> None:
        self.rollbacks += 1


class _Source:
    """A source whose records and failure point are both controllable.

    `fail_after` makes `fetch` raise once it has yielded that many records,
    which is how a run is interrupted part-way through with rows already landed.
    """

    name = "wazuh"
    table = "raw_wazuh.alerts"

    def __init__(
        self,
        marks: list[str],
        *,
        fail_after: int | None = None,
        failure: type[BaseException] = RuntimeError,
    ) -> None:
        self.marks = marks
        self.fail_after = fail_after
        self.failure = failure
        self.seen_cursor: Any = "<not called>"

    def authenticate(self) -> object:
        return object()

    def fetch(self, creds: object, cursor: str | None) -> Any:
        self.seen_cursor = cursor
        for i, mark in enumerate(self.marks):
            if self.fail_after is not None and i >= self.fail_after:
                raise self.failure("interrupted mid-fetch")
            yield {"mark": mark}

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return (record["mark"], None, record["mark"], run_id)

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return record["mark"]


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch every db call `execute()` makes and record what it did."""
    conn = _FakeConn()
    calls: dict[str, Any] = {
        "conn": conn,
        "landed": [],        # rows passed to upsert_many, per call
        "watermarks": [],    # every set_watermark value, in order
        "finished": [],      # (status, read, written) per finish_run
        "cursor_in": None,   # what get_watermark returned
    }

    def start_run(conn: object, source: str, **kw: Any) -> int:
        # **kw deliberately: a sibling change adds an invocation_id keyword, and
        # a fake with fixed parameters would raise TypeError rather than fail
        # for a reason anyone could read.
        return 42

    def upsert_many(conn: object, table: str, rows: Any, **kw: Any) -> int:
        rows = list(rows)
        calls["landed"].append(rows)
        return len(rows)

    def set_watermark(conn: object, source: str, value: Any) -> None:
        calls["watermarks"].append(value)

    def finish_run(
        conn: object, run_id: int, status: str, read: int, written: int, err: Any = None
    ) -> None:
        calls["finished"].append((status, read, written))

    monkeypatch.setattr(run_mod.db, "connect", lambda provider=None: conn)
    # execute() verifies the control schema immediately after connecting, which
    # reaches for conn.cursor(). These tests are about where the CURSOR ends up,
    # not about schema validation, and the fake connection deliberately
    # implements only what the watermark path touches.
    #
    # Patched rather than satisfied: giving _FakeConn a cursor would couple
    # every test here to whatever queries the schema check happens to run, so
    # the next change to that check would break nine unrelated tests again --
    # which is exactly how these nine came to be red on main.
    monkeypatch.setattr(
        run_mod.schema_check, "verify_control_schema", lambda conn: None
    )
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "start_run", start_run)
    monkeypatch.setattr(
        run_mod.db, "get_watermark", lambda conn, name: calls["cursor_in"]
    )
    monkeypatch.setattr(run_mod.db, "upsert_many", upsert_many)
    monkeypatch.setattr(run_mod.db, "set_watermark", set_watermark)
    monkeypatch.setattr(run_mod.db, "finish_run", finish_run)
    return calls


# -- the cursor on a clean run -------------------------------------------------


def test_a_clean_run_advances_the_cursor_to_the_highest_mark(
    harness: dict[str, Any],
) -> None:
    src = _Source(["2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z"])
    result = run_mod.execute(src, batch_size=10)

    assert result.status == "SUCCESS"
    assert harness["watermarks"] == ["2026-01-03T00:00:00Z"]


def test_the_cursor_takes_the_highest_mark_not_the_last_one_seen(
    harness: dict[str, Any],
) -> None:
    """Out-of-order arrival must not move the cursor backwards.

    A source that pages by relevance, or merges two upstream feeds, can yield an
    older record after a newer one. Taking the last mark would park the cursor
    before records already stored, and the next run would re-read them forever.
    """
    src = _Source(
        [
            "2026-01-05T00:00:00Z",
            "2026-01-02T00:00:00Z",   # older, arrives second
            "2026-01-04T00:00:00Z",
        ]
    )
    run_mod.execute(src, batch_size=10)

    assert harness["watermarks"] == ["2026-01-05T00:00:00Z"]


def test_the_cursor_is_written_once_not_once_per_batch(
    harness: dict[str, Any],
) -> None:
    """Pins the current shape, which is what §4 changes.

    Five records at batch_size=2 land in three batches. Today that is three
    commits and ONE cursor write. §4 makes the cursor advance with the batches
    for sources that may do so, at which point this expectation changes -- and
    the diff should show it changing.
    """
    src = _Source([f"2026-01-0{n}T00:00:00Z" for n in range(1, 6)])
    run_mod.execute(src, batch_size=2)

    assert len(harness["landed"]) == 3, "three batches"
    assert len(harness["watermarks"]) == 1, "but a single cursor write"


def test_a_run_that_reads_nothing_leaves_the_cursor_alone(
    harness: dict[str, Any],
) -> None:
    """An empty result must not reset the cursor.

    `high_watermark` stays None, and writing that would send the next run back
    to the beginning of time.
    """
    harness["cursor_in"] = "2026-01-01T00:00:00Z"
    run_mod.execute(_Source([]), batch_size=10)

    assert harness["watermarks"] == []
    assert harness["finished"] == [("SUCCESS", 0, 0)]


def test_the_cursor_read_at_the_start_is_handed_to_fetch(
    harness: dict[str, Any],
) -> None:
    harness["cursor_in"] = "2026-02-02T00:00:00Z"
    src = _Source(["2026-02-03T00:00:00Z"])
    run_mod.execute(src, batch_size=10)

    assert src.seen_cursor == "2026-02-02T00:00:00Z"


def test_a_dry_run_neither_lands_rows_nor_moves_the_cursor(
    harness: dict[str, Any],
) -> None:
    src = _Source(["2026-01-09T00:00:00Z"])
    result = run_mod.execute(src, dry_run=True, batch_size=10)

    assert result.status == "SUCCESS"
    assert result.rows_written == 0
    assert harness["watermarks"] == []
    assert harness["landed"] == [], "dry run must not reach upsert_many"


# -- the livelock --------------------------------------------------------------


def test_LIVELOCK_an_interrupted_run_lands_rows_and_keeps_its_old_cursor(
    harness: dict[str, Any],
) -> None:
    """THIS ASSERTS THE BUG. §4 exists to change it.

    Four records, batch_size=2, failing at the fifth fetch. The first two
    batches reached `upsert_many`, which calls `conn.commit()` itself
    (common/db.py), so those rows are DURABLE. `set_watermark` sits after the
    loop and never runs, so the cursor still points where the run started.

    The next run therefore re-reads the same window, lands the same rows, and
    fails at the same place. Nothing is corrupted and nothing progresses: rows
    accumulate, the cursor does not move, and `Result=FAILED` is the only
    symptom. A source whose catch-up exceeds the time budget can never finish,
    which is the livelock in §3.1.

    When §4 lands, the expectation becomes: the cursor sits at the highest mark
    of the batches that actually committed.
    """
    harness["cursor_in"] = "2026-01-01T00:00:00Z"
    src = _Source(
        [
            "2026-01-02T00:00:00Z",
            "2026-01-03T00:00:00Z",
            "2026-01-04T00:00:00Z",
            "2026-01-05T00:00:00Z",
            # Never yielded: fetch raises on reaching it. With only four marks
            # the loop would simply end and the run would SUCCEED, which is a
            # different test entirely.
            "2026-01-06T00:00:00Z",
        ],
        fail_after=4,
    )

    with pytest.raises(RuntimeError):
        run_mod.execute(src, batch_size=2)

    assert len(harness["landed"]) == 2, "two batches committed before the failure"
    assert [r[0] for b in harness["landed"] for r in b] == [
        "2026-01-02T00:00:00Z",
        "2026-01-03T00:00:00Z",
        "2026-01-04T00:00:00Z",
        "2026-01-05T00:00:00Z",
    ], "four rows are durable"
    assert harness["watermarks"] == [], "and the cursor was never advanced"
    assert harness["finished"] == [("FAILED", 4, 4)]


def test_an_interrupted_run_rolls_back_before_recording_the_failure(
    harness: dict[str, Any],
) -> None:
    """Correct today, and easy to lose in a rewrite.

    After an in-transaction error PostgreSQL rejects every later statement with
    InFailedSqlTransaction, so without this rollback the `finish_run` write
    would raise too and leave the row RUNNING forever -- masking the real error
    behind a bookkeeping one.
    """
    src = _Source(["2026-01-02T00:00:00Z"], fail_after=0)

    with pytest.raises(RuntimeError):
        run_mod.execute(src, batch_size=2)

    assert harness["conn"].rollbacks == 1
    assert harness["finished"] == [("FAILED", 0, 0)]


def test_LIVELOCK_a_BaseException_leaves_the_run_row_RUNNING(
    harness: dict[str, Any],
) -> None:
    """THIS ASSERTS THE BUG. The run ledger keeps a row that never resolves.

    `execute()` catches `Exception`, which by design excludes `BaseException`
    (KeyboardInterrupt, SystemExit). Such a failure skips the handler entirely:
    no rollback, no `finish_run`, so `control.ingest_run` keeps a RUNNING row
    for a run that has already ended.

    STAND-IN, NOT A SIMULATION. A real SIGTERM at `TimeoutStartSec` is more
    abrupt still -- with no handler installed the interpreter is terminated and
    NO Python-level exception is raised at all, so not even a `finally` would
    run. This test cannot reproduce that; it reproduces the same OUTCOME
    (RUNNING forever) through the nearest thing expressible in-process, and
    pins the fact that the `except Exception` clause is not a backstop for
    process termination. §4's SIGTERM handler is what makes the real case
    recoverable, by turning the signal into something Python can unwind.
    """
    src = _Source(["2026-01-02T00:00:00Z"], fail_after=0, failure=KeyboardInterrupt)

    with pytest.raises(KeyboardInterrupt):
        run_mod.execute(src, batch_size=2)

    assert harness["finished"] == [], "no terminal status was ever recorded"
    assert harness["conn"].rollbacks == 0, "and nothing was rolled back"
