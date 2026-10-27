"""Transform targets against a real PostgreSQL: behaviour, not SQL text.

WHY THIS FILE EXISTS. Every other test in tests/transform asserts on the SQL as
a *string*. That found nothing in two production failures and actively agreed
with one of them:

  * `(payload->>'severity')::int` was asserted present by a passing test. XSOAR
    severity is fractional (0.5 is Informational), so both XSOAR-sourced
    transforms failed on every run from first schedule and two marts stayed
    empty. Three reviews read that test and agreed with it.
  * `join_status` classified on `dbotMirrorId` being non-empty, read as "came
    from XDR". XSOAR sets it for any mirroring integration, so 187 ZeroFox
    incidents sat in `pending_xdr` as a backlog that was never arriving.

Neither is visible in a string. Both are obvious the moment real values go
through real SQL. So this file executes the targets and asserts on the ROWS.

Skipped unless SECOPS_TEST_DSN is set, matching tests/packs/test_state_integration.py,
so `pytest` on a laptop with no server still passes::

    docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=secops \
        postgres:16
    SECOPS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:5433/secops \
        pytest tests/transform/test_transform_integration.py -v

Fixtures carry the MEASURED domain, not a tidy one. A fixture built from what
the author expects is where both bugs above were already baked in before any
test ran.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

from secops_ingest.schema import control_sql, ddl_for_targets  # noqa: E402
from secops_ingest.transform import runner  # noqa: E402
from secops_ingest.transform.targets import (  # noqa: E402
    INCIDENT_LIFECYCLE,
    KSAT_ENROLLMENTS,
    XDR_ENDPOINTS,
    XDR_INCIDENTS,
    XSOAR_INCIDENTS,
)

TARGETS = [
    XSOAR_INCIDENTS, XDR_INCIDENTS, INCIDENT_LIFECYCLE, KSAT_ENROLLMENTS, XDR_ENDPOINTS,
]

# The full measured severity domain from a live XSOAR instance over 5,766
# incidents, including the 0.5 that broke production. Counts were
# 0:19  0.5:131  1:220  2:3369  3:1235  4:792.
XSOAR_SEVERITIES = ["0", "0.5", "1", "2", "3", "4"]

# Measured brands, with their real id shapes. XDR incident ids are 5 digits,
# ZeroFox's are 9 -- which is how we know dbotMirrorId is not an XDR reference.
XDR_BRAND = "Cortex XDR - IR"
ZEROFOX_BRAND = "ZeroFox"
MANUAL_BRAND = "Manual"


class DatabaseLooksLive(RuntimeError):
    """The target database appears to hold real warehouse data.

    This fixture drops `control` and both raw schemas. `control` carries
    `transform_coverage`, the ledger that makes raw partition expiry safe, so
    destroying it does not merely lose test rows -- it arms silent data loss
    across the whole warehouse. The realistic accident is pointing
    SECOPS_TEST_DSN at the value of SECOPS_DB_DSN.
    """


def _refuse_if_live(conn: Any) -> None:
    """Refuse to touch a database that shows evidence of real use.

    Evidence-based rather than name-based: a database-name allowlist would not
    catch `secops_warehouse_test` pointed at production by a copied DSN, and
    would reject a perfectly good scratch database called anything else.
    """
    for table in ("control.ingest_run", "control.transform_run", "control.pack"):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT to_regclass(%s) IS NOT NULL", (table,)
            )
            row = cur.fetchone()
            if not (row and row[0]):
                continue
            cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed literals
            count = cur.fetchone()
            if count and count[0]:
                raise DatabaseLooksLive(
                    f"{table} holds {count[0]} row(s). Refusing to drop schemas in "
                    "this database. Point SECOPS_TEST_DSN at a scratch database."
                )


@pytest.fixture(scope="session")
def scratch_dsn() -> str:
    """The DSN, checked once for signs of being a real warehouse.

    SESSION-SCOPED DELIBERATELY. The check has to run before this file creates
    anything, because the first test writes a control.transform_run row -- and
    a per-test check would then refuse the second test on the evidence of the
    first. "Is this a real warehouse" is a property of the database, so it is
    answered once, at the start, on the state we were handed.
    """
    dsn = os.environ["SECOPS_TEST_DSN"]
    with psycopg.connect(dsn, autocommit=True) as conn:
        _refuse_if_live(conn)
    return dsn


@pytest.fixture
def warehouse(scratch_dsn: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """A warehouse with the real generated DDL and nothing else."""
    dsn = scratch_dsn
    # runner.execute() resolves its own connection from SECOPS_DB_DSN.
    monkeypatch.setenv("SECOPS_DB_DSN", dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DROP SCHEMA IF EXISTS control CASCADE;"
                "DROP SCHEMA IF EXISTS raw_xsoar CASCADE;"
                "DROP SCHEMA IF EXISTS raw_xdr CASCADE;"
                "DROP SCHEMA IF EXISTS raw_ksat CASCADE;"
            )
            for t in TARGETS:
                cur.execute(f"DROP TABLE IF EXISTS {t.fact_table} CASCADE")
            cur.execute(control_sql())
            # behind=4: the fixtures reach back ~400 days for the aged-out case,
            # and a row with no partition fails the insert, not the assertion.
            cur.execute(ddl_for_targets(TARGETS, behind=18, ahead=3))
        yield conn


def _land_xsoar(
    conn: Any,
    incident_id: str,
    *,
    severity: str,
    brand: str,
    mirror_id: str = "",
    created: datetime | None = None,
    closed_after: timedelta | None = timedelta(hours=2),
) -> None:
    created = created or datetime.now(UTC) - timedelta(days=1)
    payload: dict[str, Any] = {
        "id": incident_id,
        "created": created.isoformat().replace("+00:00", "Z"),
        "modified": created.isoformat().replace("+00:00", "Z"),
        # XSOAR's "never closed" sentinel is a zero date, not null or "".
        "closed": (
            (created + closed_after).isoformat().replace("+00:00", "Z")
            if closed_after
            else "0001-01-01T00:00:00Z"
        ),
        "status": "2",
        "severity": severity,
        "sourceBrand": brand,
        "type": "Phishing",
        "owner": "analyst",
        "dbotMirrorId": mirror_id,
    }
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO raw_xsoar.incidents"
            " (source_id, payload, _event_time, _ingested_at) VALUES (%s, %s, %s, now())",
            (incident_id, json.dumps(payload), created),
        )


def _land_xdr(conn: Any, incident_id: str, *, created: datetime | None = None) -> None:
    created = created or datetime.now(UTC) - timedelta(days=1)
    ms = int(created.timestamp() * 1000)
    payload = {
        "incident_id": incident_id,
        "creation_time": ms,
        "modification_time": ms,
        "resolved_timestamp": ms + 3_600_000,
        "status": "resolved_true_positive",
        "severity": "medium",
        "description": "d",
        "alert_count": 3,
        "high_severity_alert_count": 1,
        "med_severity_alert_count": 1,
        "low_severity_alert_count": 1,
        "host_count": 1,
        "user_count": 1,
        "assigned_user_mail": "a@example.com",
    }
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO raw_xdr.incidents"
            " (source_id, payload, _event_time, _ingested_at) VALUES (%s, %s, %s, now())",
            (incident_id, json.dumps(payload), created),
        )


def _rows(conn: Any, query: str) -> list[tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(query)
        return list(cur.fetchall())


def test_fractional_severity_survives_the_transform(warehouse: Any) -> None:
    """0.5 reaches the mart as 0.5.

    An integer column would not error here -- assignment ROUNDS, so 0.5 lands
    as 1 and the run reports SUCCESS. That is why this asserts the value and
    not the status.
    """
    for i, sev in enumerate(XSOAR_SEVERITIES):
        _land_xsoar(warehouse, f"inc{i}", severity=sev, brand=XDR_BRAND)

    result = runner.execute(XSOAR_INCIDENTS)
    assert result.rows_upserted == len(XSOAR_SEVERITIES)

    got = _rows(
        warehouse,
        "SELECT severity::text FROM mart_fact_xsoar_incidents ORDER BY severity",
    )
    assert [r[0] for r in got] == ["0", "0.5", "1", "2", "3", "4"]


def test_zerofox_incidents_are_not_a_pending_xdr_backlog(warehouse: Any) -> None:
    """A mirrored non-XDR incident is `non_xdr_source`, not `pending_xdr`.

    ZeroFox mirrors into XSOAR with dbotMirrorId set, so the old
    `dbotMirrorId = ''` test classified 187 of them as XDR rows that had not
    arrived yet. Nine-digit id on purpose: XDR incident ids are five.
    """
    _land_xsoar(
        warehouse, "zf1", severity="0.5", brand=ZEROFOX_BRAND, mirror_id="594146910"
    )
    runner.execute(XDR_INCIDENTS)
    runner.execute(INCIDENT_LIFECYCLE)

    assert _rows(
        warehouse, "SELECT join_status FROM mart_fact_incident_lifecycle"
    ) == [("non_xdr_source",)]


def test_each_brand_lands_in_its_own_bucket(warehouse: Any) -> None:
    """The four join_status values, one fixture each, measured shapes.

    Covers the whole CASE in one pass so a change to any branch cannot be
    green by virtue of the others.
    """
    now = datetime.now(UTC)
    # matched: XDR-branded, and its XDR row is present.
    _land_xdr(warehouse, "45220")
    _land_xsoar(warehouse, "x1", severity="2", brand=XDR_BRAND, mirror_id="45220")
    # pending_xdr: XDR-branded, recent, XDR row not landed.
    _land_xsoar(warehouse, "x2", severity="3", brand=XDR_BRAND, mirror_id="45221")
    # xdr_aged_out: XDR-branded, older than XDR's 325-day retention.
    _land_xsoar(
        warehouse,
        "x3",
        severity="1",
        brand=XDR_BRAND,
        mirror_id="39605",
        created=now - timedelta(days=400),
    )
    # non_xdr_source, two ways: mirrored from another product, and manual.
    _land_xsoar(
        warehouse, "zf1", severity="0.5", brand=ZEROFOX_BRAND, mirror_id="561641488"
    )
    _land_xsoar(warehouse, "m1", severity="0", brand=MANUAL_BRAND)

    runner.execute(XDR_INCIDENTS)
    runner.execute(INCIDENT_LIFECYCLE)

    got = dict(
        _rows(
            warehouse,
            "SELECT join_status, count(*)::int FROM mart_fact_incident_lifecycle"
            " GROUP BY 1",
        )
    )
    assert got == {
        "matched": 1,
        "pending_xdr": 1,
        "xdr_aged_out": 1,
        "non_xdr_source": 2,
    }


def test_full_refresh_reclassifies_without_a_watermark_reset(warehouse: Any) -> None:
    """A late XDR arrival flips pending_xdr to matched on the next run.

    The reclassification this fix relies on in production: 187 rows change
    label with no backfill and no migration, because the target is
    full_refresh. If full_refresh regressed, the second run would skip the
    upsert entirely and this stays 'pending_xdr'.
    """
    _land_xsoar(warehouse, "x1", severity="2", brand=XDR_BRAND, mirror_id="45220")
    runner.execute(INCIDENT_LIFECYCLE)
    assert _rows(
        warehouse, "SELECT join_status FROM mart_fact_incident_lifecycle"
    ) == [("pending_xdr",)]

    _land_xdr(warehouse, "45220")
    runner.execute(XDR_INCIDENTS)
    second = runner.execute(INCIDENT_LIFECYCLE)

    assert second.rows_upserted == 1, "full_refresh should re-derive the existing row"
    assert _rows(
        warehouse, "SELECT join_status FROM mart_fact_incident_lifecycle"
    ) == [("matched",)]


# ---------------------------------------------------------------------------
# KSAT enrollments
#
# This source is RE-READ in full every run rather than tailed, because the API
# exposes no mutation axis (see sources/ksat.py). So the behaviour that matters
# is not "does a new row land" -- it is "does a row that CHANGED get refreshed
# in place". A fixture that only ever lands fresh enrollments would pass
# against an upsert that silently freezes the first status it ever saw, which
# is the same shape as the dbotMirrorId defect above.
# ---------------------------------------------------------------------------


def _z(dt: datetime) -> str:
    """KSAT emits Z-suffixed UTC, not +00:00."""
    return dt.isoformat().replace("+00:00", "Z")


def _land_ksat(
    conn: Any,
    enrollment_id: str,
    *,
    status: str,
    created: datetime,
    score: Any = None,
    time_spent: Any = None,
    completed: datetime | None = None,
    campaign_id: str = "771",
    campaign_name: str = "2026 Q4 Security Awareness",
    user_id: str = "u-9001",
    ingested: datetime | None = None,
) -> None:
    """Land one enrollment as the connector would.

    `_event_time` is createdAt, which is immutable across the enrollment's
    lifecycle -- that is what makes the upsert key stable while every other
    column moves. The campaign arrives NESTED, because fetch() attaches the
    whole campaign object to each enrollment rather than flattening it.
    """
    payload: dict[str, Any] = {
        "id": enrollment_id,
        "status": status,
        "createdAt": _z(created),
        "updatedAt": _z(completed or created),
        "startedAt": None if status == "NOT_STARTED" else _z(created),
        "completedAt": _z(completed) if completed else None,
        "lastStartedAt": None if status == "NOT_STARTED" else _z(created),
        "timeSpentInSeconds": time_spent,
        "score": score,
        "policyAcknowledged": status == "COMPLETED",
        "user": {"id": user_id, "archived": False},
        "campaign": {
            "id": campaign_id,
            "name": campaign_name,
            "status": "In Progress",
            "startDate": created.date().isoformat(),
            "endDate": None,
            "percentComplete": 42,
        },
    }
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO raw_ksat.enrollments"
            " (source_id, payload, _event_time, _ingested_at, _source_run_id)"
            " VALUES (%s, %s, %s, %s, 1)"
            " ON CONFLICT (source_id, _event_time) DO UPDATE SET"
            "   payload = EXCLUDED.payload, _ingested_at = EXCLUDED._ingested_at",
            (enrollment_id, json.dumps(payload), created,
             ingested or datetime.now(UTC)),
        )


def test_an_enrollment_that_progresses_is_refreshed_in_place(warehouse: Any) -> None:
    """NOT_STARTED -> COMPLETED must update the fact row, not add a second one.

    The whole reason this source is re-read is that enrollments change status
    long after they are created. An upsert whose DO UPDATE list omits status
    would leave every enrollment reading NOT_STARTED forever, and the row count
    would look perfectly healthy.
    """
    conn = warehouse
    created = datetime.now(UTC) - timedelta(days=30)

    _land_ksat(conn, "e-1", status="NOT_STARTED", created=created)
    runner.execute(KSAT_ENROLLMENTS)

    done = created + timedelta(days=5)
    _land_ksat(conn, "e-1", status="COMPLETED", created=created,
               completed=done, score=88, time_spent=1320)
    runner.execute(KSAT_ENROLLMENTS)

    rows = _rows(
        conn,
        "SELECT enrollment_id, status, completed_at, score, time_spent_s,"
        " started_at, updated_at, policy_acknowledged"
        " FROM mart_fact_ksat_enrollments",
    )
    assert len(rows) == 1, f"expected one row per enrollment, got {rows}"
    assert rows[0][1] == "COMPLETED"
    assert rows[0][2] is not None, "completed_at was never refreshed"
    assert rows[0][3] == 88
    assert rows[0][4] == 1320
    # EVERY mutable column, not just the ones a reader thinks of. Omitting one
    # from the DO UPDATE list freezes it at whatever the first run saw -- the
    # dbotMirrorId defect, which sat on the single column the integration
    # joined on.
    assert rows[0][5] is not None, "started_at was never refreshed"
    assert rows[0][6] is not None, "updated_at was never refreshed"
    assert rows[0][7] is True, "policy_acknowledged was never refreshed"


def test_a_fractional_score_survives_the_transform(warehouse: Any) -> None:
    """score is numeric, not integer.

    Exactly the XSOAR severity defect: an ::int cast does not reject 87.5, it
    aborts the whole upsert with "invalid input syntax for type integer", and
    the mart stays empty. KSAT scores are percentages and nothing promises they
    are whole.
    """
    conn = warehouse
    created = datetime.now(UTC) - timedelta(days=10)
    _land_ksat(conn, "e-frac", status="COMPLETED", created=created,
               completed=created + timedelta(hours=2), score=87.5, time_spent=600)
    runner.execute(KSAT_ENROLLMENTS)

    rows = _rows(conn, "SELECT score FROM mart_fact_ksat_enrollments"
                       " WHERE enrollment_id = 'e-frac'")
    assert rows == [(Decimal("87.5"),)], rows


def test_the_nested_campaign_is_flattened_onto_the_fact(warehouse: Any) -> None:
    """The campaign arrives as a nested object, not as flat keys.

    payload->>'campaign' on a nested object yields the JSON TEXT of the whole
    object, so a dashboard would render {"id": "771", ...} as the campaign
    name. It has to be payload->'campaign'->>'name'.
    """
    conn = warehouse
    created = datetime.now(UTC) - timedelta(days=3)
    _land_ksat(conn, "e-camp", status="IN_PROGRESS", created=created,
               campaign_id="903", campaign_name="Phishing Fundamentals")
    runner.execute(KSAT_ENROLLMENTS)

    rows = _rows(conn, "SELECT campaign_id, campaign_name, campaign_status"
                       " FROM mart_fact_ksat_enrollments"
                       " WHERE enrollment_id = 'e-camp'")
    assert rows == [("903", "Phishing Fundamentals", "In Progress")], rows


def test_a_not_started_enrollment_lands_with_null_outcomes(warehouse: Any) -> None:
    """An unstarted enrollment has null score, timeSpent and completedAt.

    JSON null reaches SQL as the string "null" through ->> only if you ask for
    the wrong thing; the cast has to see a real NULL or it fails the run. The
    row must still land -- an enrollment nobody has opened is a reportable fact,
    and dropping it would understate every denominator.
    """
    conn = warehouse
    created = datetime.now(UTC) - timedelta(days=1)
    _land_ksat(conn, "e-fresh", status="NOT_STARTED", created=created)
    runner.execute(KSAT_ENROLLMENTS)

    rows = _rows(
        conn,
        "SELECT status, score, time_spent_s, completed_at, started_at,"
        " policy_acknowledged, user_id, user_archived"
        " FROM mart_fact_ksat_enrollments"
        " WHERE enrollment_id = 'e-fresh'",
    )
    assert rows == [
        ("NOT_STARTED", None, None, None, None, False, "u-9001", False)
    ], rows


# ---------------------------------------------------------------------------
# Chunking, wind-down bookkeeping, and the target lock
#
# The upsert used to be one statement under the role's 900s statement_timeout.
# A backlog longer than that was cancelled, the watermark held, and the same
# statement was cancelled on every run after. These drive the chunked path
# through real SQL: the slices have to cover the backlog exactly, and a failure
# part-way has to keep what was committed before it.
# ---------------------------------------------------------------------------

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _ingested(conn: Any, incident_id: str, at: datetime) -> None:
    """Pin a raw row's _ingested_at, so chunk boundaries are deterministic."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE raw_xsoar.incidents SET _ingested_at = %s WHERE source_id = %s",
            (at, incident_id),
        )


def _runs(conn: Any, target: str) -> list[tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status, rows_upserted, error_summary FROM control.transform_run"
            " WHERE target = %s ORDER BY run_id",
            (target,),
        )
        return list(cur.fetchall())


def _mark(conn: Any, target: str) -> Any:
    rows = _rows(
        conn,
        "SELECT cursor_value FROM control.transform_watermark"
        f" WHERE target = '{target}'",  # noqa: S608 - fixed literal
    )
    return rows[0][0] if rows else None


def test_a_backlog_lands_in_chunks_with_nothing_missed(warehouse: Any) -> None:
    for i in range(7):
        _land_xsoar(warehouse, f"c{i}", severity="2", brand=XDR_BRAND)
        _ingested(warehouse, f"c{i}", T0 + timedelta(minutes=i))

    result = runner.execute(XSOAR_INCIDENTS, chunk_rows=2)

    assert result.status == "SUCCESS"
    assert result.rows_upserted == 7
    assert _rows(warehouse, "SELECT count(*) FROM mart_fact_xsoar_incidents") == [(7,)]
    assert _mark(warehouse, "xsoar_incidents") == T0 + timedelta(minutes=6)
    assert _runs(warehouse, "xsoar_incidents") == [("SUCCESS", 7, None)]


def test_a_failing_chunk_keeps_every_chunk_before_it(warehouse: Any) -> None:
    """THE LIVELOCK, INVERTED. A statement cancelled part-way through a backlog
    used to keep nothing. Now the chunks before it are committed and the
    watermark sits at the top of the last one, so the next run starts there."""
    for i in range(4):
        _land_xsoar(warehouse, f"ok{i}", severity="2", brand=XDR_BRAND)
        _ingested(warehouse, f"ok{i}", T0 + timedelta(minutes=i))
    # Not a number: the ::numeric cast aborts whichever chunk holds it.
    _land_xsoar(warehouse, "bad", severity="high", brand=XDR_BRAND)
    _ingested(warehouse, "bad", T0 + timedelta(minutes=10))

    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        runner.execute(XSOAR_INCIDENTS, chunk_rows=2)

    assert _rows(warehouse, "SELECT count(*) FROM mart_fact_xsoar_incidents") == [(4,)]
    assert _mark(warehouse, "xsoar_incidents") == T0 + timedelta(minutes=3)
    [(status, rows, why)] = _runs(warehouse, "xsoar_incidents")
    assert (status, rows) == ("FAILED", 4)
    assert "after 2 committed chunk(s), 4 row(s)" in why


def test_a_run_past_its_deadline_is_failed_not_running(warehouse: Any) -> None:
    _land_xsoar(warehouse, "d1", severity="2", brand=XDR_BRAND)

    result = runner.execute(XSOAR_INCIDENTS, deadline_sec=0)

    assert result.status == "FAILED"
    [(status, rows, why)] = _runs(warehouse, "xsoar_incidents")
    assert (status, rows) == ("FAILED", 0)
    assert why.startswith("stopped at the 0s deadline after 0 chunk(s)")


def test_full_refresh_in_chunks_still_classifies_every_row(warehouse: Any) -> None:
    """The lifecycle join's pending_xdr retry branch sits under the chunk bound
    too; one row per chunk proves no row falls between two slices."""
    _land_xdr(warehouse, "45220")
    _land_xsoar(warehouse, "x1", severity="2", brand=XDR_BRAND, mirror_id="45220")
    _land_xsoar(warehouse, "x2", severity="3", brand=XDR_BRAND, mirror_id="45221")
    _land_xsoar(warehouse, "m1", severity="0", brand=MANUAL_BRAND)
    for i, inc in enumerate(("x1", "x2", "m1")):
        _ingested(warehouse, inc, T0 + timedelta(minutes=i))
    runner.execute(XDR_INCIDENTS)

    result = runner.execute(INCIDENT_LIFECYCLE, chunk_rows=1)

    # 4, not 3: once chunk 2 has written x2 as pending_xdr, chunk 3's retry
    # branch re-derives it. Idempotent, and the count of statements' rows
    # rather than of distinct incidents -- which is why the mart is asserted.
    assert result.rows_upserted == 4
    assert _rows(warehouse, "SELECT count(*) FROM mart_fact_incident_lifecycle") == [(3,)]
    assert dict(_rows(
        warehouse,
        "SELECT xsoar_incident_id, join_status FROM mart_fact_incident_lifecycle",
    )) == {"x1": "matched", "x2": "pending_xdr", "m1": "non_xdr_source"}


def test_abandoned_running_rows_are_closed_by_the_next_run(warehouse: Any) -> None:
    """A SIGKILLed run leaves RUNNING forever; the next run of that target
    closes it. A young RUNNING row, or another target's, is left alone."""
    with warehouse.cursor() as cur:
        cur.execute(
            "INSERT INTO control.transform_run (target, status, started_at) VALUES"
            " ('xsoar_incidents', 'RUNNING', now() - interval '2 hours'),"
            " ('xsoar_incidents', 'RUNNING', now() - interval '1 minute'),"
            " ('xdr_incidents',   'RUNNING', now() - interval '2 hours')"
        )
    _land_xsoar(warehouse, "r1", severity="2", brand=XDR_BRAND)

    runner.execute(XSOAR_INCIDENTS)

    got = _rows(
        warehouse,
        "SELECT target, status, left(error_summary, 10) FROM control.transform_run"
        " ORDER BY run_id",
    )
    assert got == [
        ("xsoar_incidents", "FAILED", "abandoned:"),
        ("xsoar_incidents", "RUNNING", None),
        ("xdr_incidents", "RUNNING", None),
        ("xsoar_incidents", "SUCCESS", None),
    ]


def test_a_target_locked_elsewhere_writes_nothing(warehouse: Any, scratch_dsn: str) -> None:
    """The literal lock `packs drop` must also take. Spelled out rather than
    imported, so a change to the key breaks this test, not the coordination."""
    _land_xsoar(warehouse, "l1", severity="2", brand=XDR_BRAND)
    with psycopg.connect(scratch_dsn, autocommit=True) as other:
        other.execute(
            "SELECT pg_advisory_lock(hashtext('secops_ingest.transform'),"
            " hashtext('xsoar_incidents'))"
        )
        result = runner.execute(XSOAR_INCIDENTS)

    assert result.status == "BUSY"
    assert _runs(warehouse, "xsoar_incidents") == []
    # Released with the other session, so the next run proceeds normally.
    assert runner.execute(XSOAR_INCIDENTS).status == "SUCCESS"


def test_a_disabled_pack_transforms_nothing(warehouse: Any) -> None:
    from secops_ingest.packs import state as pack_state

    _land_xsoar(warehouse, "p1", severity="2", brand=XDR_BRAND)
    pack_state.set_state(warehouse, "builtin", "0.1.0", "DISABLED")

    result = runner.execute(XSOAR_INCIDENTS)

    assert result.status == "DISABLED"
    assert _runs(warehouse, "xsoar_incidents") == []
    assert _rows(warehouse, "SELECT count(*) FROM mart_fact_xsoar_incidents") == [(0,)]


def test_stale_raw_records_why_nothing_moved(warehouse: Any) -> None:
    _land_xsoar(warehouse, "s1", severity="2", brand=XDR_BRAND)
    runner.execute(XSOAR_INCIDENTS)

    second = runner.execute(XSOAR_INCIDENTS)

    assert second.status == "SUCCESS"
    status, rows, why = _runs(warehouse, "xsoar_incidents")[-1]
    assert (status, rows) == ("SUCCESS", 0)
    assert why.startswith("nothing new: raw_xsoar.incidents last received rows at")


# ---------------------------------------------------------------------------
# xdr_endpoints: whole snapshots only
#
# Every row of one ingest run is one picture of the estate under one
# snapshot_at. A run that failed or stopped part-way has committed half of it,
# and copying that reads as agents vanishing. The target copies a run's rows
# only once control.ingest_run says SUCCESS with no note, holds its watermark
# below a run still in progress, and names every run it left out.
# ---------------------------------------------------------------------------


def _ingest_run(
    conn: Any, status: str, *, note: str | None = None,
    started: timedelta = timedelta(minutes=5),
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.ingest_run (source, status, error_summary, started_at)"
            " VALUES ('xdr_endpoints', %s, %s, now() - %s) RETURNING run_id",
            (status, note, started),
        )
        row = cur.fetchone()
    assert row is not None
    return int(row[0])


def _land_snapshot(
    conn: Any, run_id: int, snapshot_at: datetime, ingested: datetime, n: int = 2
) -> None:
    with conn.cursor() as cur:
        for i in range(n):
            cur.execute(
                "INSERT INTO raw_xdr.endpoint_snapshots"
                " (source_id, payload, _event_time, _ingested_at, _source_run_id)"
                " VALUES (%s, %s, %s, %s, %s)",
                (f"ep{i}", json.dumps({"endpoint_name": f"host{i}",
                                       "endpoint_status": "CONNECTED"}),
                 snapshot_at, ingested + timedelta(seconds=i), run_id),
            )


def _snapshots(conn: Any) -> dict[datetime, int]:
    return dict(_rows(
        conn,
        "SELECT snapshot_at, count(*)::int FROM mart_fact_xdr_endpoint_snapshots"
        " GROUP BY 1",
    ))


def test_only_complete_snapshots_are_copied_and_the_rest_are_named(
    warehouse: Any,
) -> None:
    day = datetime.now(UTC).replace(microsecond=0) - timedelta(days=3)
    complete = _ingest_run(warehouse, "SUCCESS")
    failed = _ingest_run(warehouse, "FAILED", note="HTTPStatusError: 502")
    stopped = _ingest_run(warehouse, "SUCCESS", note="stopped at SIGTERM: read 1000 row(s)")
    _land_snapshot(warehouse, complete, day, T0)
    _land_snapshot(warehouse, failed, day + timedelta(days=1), T0 + timedelta(minutes=1))
    _land_snapshot(warehouse, stopped, day + timedelta(days=2), T0 + timedelta(minutes=2))

    result = runner.execute(XDR_ENDPOINTS)

    assert result.status == "SUCCESS"
    assert _snapshots(warehouse) == {day: 2}
    [(status, _, why)] = _runs(warehouse, "xdr_endpoints")
    assert status == "SUCCESS"
    assert why.startswith("skipped 4 raw row(s) from incomplete ingest run(s)")
    assert f"run {failed} FAILED: 2 row(s)" in why
    assert f"run {stopped} SUCCESS with a note (incomplete): 2 row(s)" in why
    # Skipped for good: the watermark is past them, which is the point -- a
    # half estate does not become whole by waiting.
    assert _mark(warehouse, "xdr_endpoints") == T0 + timedelta(minutes=2, seconds=1)


def test_a_snapshot_still_landing_is_held_back_and_copied_once_complete(
    warehouse: Any,
) -> None:
    """Skipping a RUNNING run's rows and moving the watermark past them would
    lose the snapshot the moment it completed. The mark has to wait for it."""
    day = datetime.now(UTC).replace(microsecond=0) - timedelta(days=2)
    done = _ingest_run(warehouse, "SUCCESS")
    live = _ingest_run(warehouse, "RUNNING", started=timedelta(minutes=1))
    _land_snapshot(warehouse, done, day, T0)
    _land_snapshot(warehouse, live, day + timedelta(days=1), T0 + timedelta(minutes=1))

    first = runner.execute(XDR_ENDPOINTS)

    assert _snapshots(warehouse) == {day: 2}
    assert _mark(warehouse, "xdr_endpoints") == T0 + timedelta(seconds=1)
    assert f"held back below ingest run(s) [{live}] still RUNNING" in (first.note or "")

    with warehouse.cursor() as cur:
        cur.execute("UPDATE control.ingest_run SET status = 'SUCCESS' WHERE run_id = %s",
                    (live,))
    second = runner.execute(XDR_ENDPOINTS)

    assert second.note is None
    assert _snapshots(warehouse) == {day: 2, day + timedelta(days=1): 2}


def test_an_abandoned_running_snapshot_does_not_hold_the_target_forever(
    warehouse: Any,
) -> None:
    """A RUNNING ingest row older than the reap age belongs to a killed
    process. Holding for it would freeze the mart; it is skipped and named."""
    day = datetime.now(UTC).replace(microsecond=0) - timedelta(days=2)
    dead = _ingest_run(warehouse, "RUNNING", started=timedelta(hours=3))
    done = _ingest_run(warehouse, "SUCCESS")
    _land_snapshot(warehouse, dead, day, T0)
    _land_snapshot(warehouse, done, day + timedelta(days=1), T0 + timedelta(minutes=1))

    result = runner.execute(XDR_ENDPOINTS)

    assert _snapshots(warehouse) == {day + timedelta(days=1): 2}
    assert f"run {dead} RUNNING, abandoned: 2 row(s)" in (result.note or "")
