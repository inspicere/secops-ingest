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
    XDR_INCIDENTS,
    XSOAR_INCIDENTS,
)

TARGETS = [XSOAR_INCIDENTS, XDR_INCIDENTS, INCIDENT_LIFECYCLE, KSAT_ENROLLMENTS]

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
