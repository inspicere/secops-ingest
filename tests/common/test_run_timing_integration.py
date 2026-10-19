"""`ended_at` must record when a run ENDED, against a real PostgreSQL.

Skipped unless SECOPS_TEST_DSN is set, matching
tests/packs/test_state_integration.py, so a laptop with no server still passes
and the suite keeps its no-database guarantee by default.

WHY THIS NEEDS A REAL SERVER. The bug it covers is a property of PostgreSQL's
transaction semantics and cannot be reproduced against a fake connection:
`now()` returns the TRANSACTION START time, not the current time. Any fake that
returns a plausible timestamp would pass whichever function the code called.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="set SECOPS_TEST_DSN to run against a real PostgreSQL",
)

from secops_ingest.common import db  # noqa: E402
from secops_ingest.schema import control_sql  # noqa: E402


@pytest.fixture
def conn() -> Iterator[psycopg.Connection]:
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"]) as c:
        with c.cursor() as cur:
            cur.execute(control_sql())
        c.commit()
        yield c


def test_ended_at_measures_the_run_not_its_transaction(conn: psycopg.Connection) -> None:
    """A run that writes nothing still has to report how long it took.

    THE BUG THIS PINS. start_run commits, so the next statement opens a fresh
    transaction. A scan that lands no rows never commits again, so that
    transaction stays open for the whole run -- and `now()` inside it returns
    the moment it opened. A 29-minute DefectDojo scan that found no changes was
    recorded as having taken 14 MILLISECONDS, with ended_at one millisecond
    before the log line announcing the run.

    Observed on a live warehouse 2026-10-19: four of five hourly runs recorded
    0 rows in 0 seconds while the journal showed each one scanning ~52,000
    findings for around half an hour. Runs that DID write rows looked correct,
    because upsert_many commits and a later statement starts a new transaction
    -- so the error hides exactly where there is nothing else to notice.

    The elapsed time asserted here is deliberately generous: the point is to
    separate "measured something" from "measured zero", not to time anything.
    """
    run_id = db.start_run(conn, "timing-test")

    # Open a transaction and hold it, which is what a scan yielding nothing
    # does. Any statement will do; this one is cheap and side-effect free.
    with conn.cursor() as cur:
        cur.execute("SELECT 1")
    time.sleep(1.1)

    db.finish_run(conn, run_id, "SUCCESS", rows_read=0, rows_written=0)

    with conn.cursor() as cur:
        cur.execute(
            "SELECT extract(epoch FROM ended_at - started_at) "
            "FROM control.ingest_run WHERE run_id = %s",
            (run_id,),
        )
        row = cur.fetchone()
    assert row is not None
    elapsed = float(row[0])
    assert elapsed >= 1.0, (
        f"ended_at - started_at was {elapsed:.3f}s for a run held open for 1.1s; "
        "ended_at is recording a transaction's start rather than the run's end"
    )
