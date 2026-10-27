"""Grants, DEFAULT partitions and the drift checks against a real PostgreSQL.

tests/schema/test_grants_and_partitions.py pins the emitted text; this file
proves that text means what it claims: each worker can write its own control
tables and no others, the read and monitor roles see what they need and no
more, a remote writer is confined to its schema, an out-of-window row lands in
DEFAULT instead of failing, and the drift checks pass under the narrowed
grants.

Skipped unless SECOPS_TEST_DSN is set, matching the other integration files.
The DSN must be a superuser (it creates throwaway roles, all prefixed
`secops_t_`, and drops them again)::

    SECOPS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:5433/secops \\
        pytest tests/schema/test_grants_integration.py -v
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

from secops_ingest.common import schema_check  # noqa: E402
from secops_ingest.schema import (  # noqa: E402
    control_sql,
    ddl_for_targets,
    grants_sql,
    partition_check_sql,
    partition_health_sql,
    partitions_sql,
)
from secops_ingest.transform.targets import TARGETS  # noqa: E402
from tests.packs.test_state_integration import _refuse_if_live  # noqa: E402

INGEST, TRANSFORM, READ, MONITOR, REMOTE = (
    "secops_t_ingest", "secops_t_transform", "secops_t_read", "secops_t_monitor",
    "secops_t_remote",
)
ROLES = (INGEST, TRANSFORM, READ, MONITOR, REMOTE)
WAZUH, XDR = TARGETS["wazuh_alerts"], TARGETS["xdr_incidents"]


def _drop_everything(conn: psycopg.Connection) -> None:
    conn.rollback()
    conn.execute("RESET ROLE")
    for schema in ("control", "raw_wazuh", "raw_xdr"):
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    for target in (WAZUH, XDR):
        for table in (target.fact_table, target.rollup_table):
            if table:
                conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for role in ROLES:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        if exists:
            conn.execute(f"DROP OWNED BY {role}")
            conn.execute(f"DROP ROLE {role}")
    conn.commit()


@pytest.fixture()
def warehouse() -> Iterator[psycopg.Connection]:
    """control + wazuh + xdr_incidents, all five roles, the new grants."""
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"], autocommit=False) as conn:
        _refuse_if_live(conn)
        _drop_everything(conn)
        for role in ROLES:
            conn.execute(f"CREATE ROLE {role}")
        conn.execute(control_sql())
        conn.execute(partition_health_sql())
        conn.execute(ddl_for_targets([WAZUH, XDR]))
        marts = [t for x in (WAZUH, XDR) for t in (x.fact_table, x.rollup_table) if t]
        conn.execute(grants_sql(
            ["raw_wazuh", "raw_xdr"], marts,
            ingest_role=INGEST, transform_role=TRANSFORM, read_role=READ,
            monitor_role=MONITOR, remote_ingest=[(REMOTE, "raw_wazuh")],
            partition_health=True,
        ))
        conn.commit()
        try:
            yield conn
        finally:
            _drop_everything(conn)


def _as(conn: psycopg.Connection, role: str, statement: str) -> bool:
    """True if `role` may run `statement`; False on a permission error."""
    try:
        with conn.transaction():
            conn.execute(f"SET LOCAL ROLE {role}")
            conn.execute(statement)
            raise _Rollback
    except _Rollback:
        return True
    except psycopg.errors.InsufficientPrivilege:
        return False


class _Rollback(Exception):
    """Raised inside a transaction block to undo a probe that succeeded."""


COVERAGE = "INSERT INTO control.transform_coverage VALUES ('t', '2026-01-01', 1)"
RUN = "INSERT INTO control.ingest_run (source) VALUES ('s')"
PACK = "INSERT INTO control.pack (name, version, state) VALUES ('p', '1', 'ENABLED')"
WAZUH_ROW = "INSERT INTO raw_wazuh.alerts VALUES ('a', '{}', now())"
XDR_ROW = "INSERT INTO raw_xdr.incidents VALUES ('a', '{}', now())"


def test_ingest_writes_its_runs_but_cannot_forge_coverage_or_packs(
    warehouse: psycopg.Connection,
) -> None:
    assert _as(warehouse, INGEST, RUN)
    assert not _as(warehouse, INGEST, COVERAGE)
    assert not _as(warehouse, INGEST, PACK)
    assert not _as(warehouse, INGEST, "DELETE FROM control.ingest_run")


def test_transform_writes_coverage_but_cannot_move_ingest_state(
    warehouse: psycopg.Connection,
) -> None:
    assert _as(warehouse, TRANSFORM, COVERAGE)
    assert not _as(warehouse, TRANSFORM, "UPDATE control.ingest_watermark SET cursor_value = 'x'")
    assert not _as(warehouse, TRANSFORM, PACK)


def test_remote_writer_is_confined_and_the_shared_role_loses_its_schema(
    warehouse: psycopg.Connection,
) -> None:
    assert _as(warehouse, REMOTE, WAZUH_ROW)
    assert not _as(warehouse, REMOTE, XDR_ROW)
    assert _as(warehouse, REMOTE, RUN)
    assert not _as(warehouse, REMOTE, COVERAGE)
    assert _as(warehouse, INGEST, XDR_ROW)
    assert not _as(warehouse, INGEST, WAZUH_ROW)


def test_read_role_reads_control_and_mart_never_raw(warehouse: psycopg.Connection) -> None:
    assert _as(warehouse, READ, "SELECT count(*) FROM control.ingest_run")
    assert _as(warehouse, READ, f"SELECT count(*) FROM {WAZUH.fact_table}")
    assert not _as(warehouse, READ, "SELECT count(*) FROM raw_wazuh.alerts")


def test_monitor_role_reads_control_and_health_only(warehouse: psycopg.Connection) -> None:
    assert _as(warehouse, MONITOR, "SELECT count(*) FROM control.transform_coverage")
    assert _as(warehouse, MONITOR, "SELECT * FROM control.partition_health()")
    assert not _as(warehouse, MONITOR, f"SELECT count(*) FROM {WAZUH.fact_table}")
    assert not _as(warehouse, MONITOR, "SELECT count(*) FROM raw_wazuh.alerts")
    assert not _as(warehouse, INGEST, "SELECT * FROM control.partition_health()")


def test_new_grants_take_away_the_old_blanket_ones(warehouse: psycopg.Connection) -> None:
    """GRANT never revokes; a warehouse converged with the old grants must
    still end up with the narrow ones."""
    warehouse.execute(
        f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA control TO {INGEST}"
    )
    assert _as(warehouse, INGEST, COVERAGE)
    warehouse.execute(grants_sql(["raw_xdr"], [], ingest_role=INGEST))
    assert not _as(warehouse, INGEST, COVERAGE)
    assert _as(warehouse, INGEST, RUN)


@pytest.mark.parametrize("role", [INGEST, TRANSFORM, REMOTE])
def test_control_drift_check_passes_under_narrow_grants(
    warehouse: psycopg.Connection, role: str
) -> None:
    """information_schema hides tables a role has no privilege on, so the
    drift check is the first thing a too-narrow grant would break."""
    warehouse.execute(f"SET ROLE {role}")
    try:
        schema_check.verify_control_schema(warehouse)
    finally:
        warehouse.rollback()
        warehouse.execute("RESET ROLE")


def test_target_drift_check_passes_then_names_a_dropped_column(
    warehouse: psycopg.Connection,
) -> None:
    warehouse.execute(f"SET ROLE {TRANSFORM}")
    schema_check.verify_target_schema(warehouse, [WAZUH, XDR])
    warehouse.execute("RESET ROLE")
    warehouse.execute(f"ALTER TABLE {WAZUH.fact_table} DROP COLUMN decoder")
    with pytest.raises(schema_check.TargetSchemaDrift, match="missing column\\(s\\): decoder"):
        schema_check.verify_target_schema(warehouse, [WAZUH])
    warehouse.rollback()


def test_an_out_of_window_row_lands_in_default_and_is_reported(
    warehouse: psycopg.Connection,
) -> None:
    warehouse.execute("INSERT INTO raw_xdr.incidents VALUES ('old', '{}', '2019-03-05')")
    where = warehouse.execute(
        "SELECT tableoid::regclass::text FROM raw_xdr.incidents WHERE source_id = 'old'"
    ).fetchone()
    assert where == ("raw_xdr.incidents_default",)
    health = dict(
        (parent, rows) for parent, rows, _until in
        warehouse.execute("SELECT * FROM control.partition_health()").fetchall()
    )
    assert health["raw_xdr.incidents"] == 1
    assert health["raw_wazuh.alerts"] == 0
    warehouse.rollback()


def test_widening_over_default_rows_skips_that_month_and_creates_the_rest(
    warehouse: psycopg.Connection,
) -> None:
    warehouse.execute("INSERT INTO raw_xdr.incidents VALUES ('old', '{}', '2019-03-05')")
    warehouse.commit()
    before = warehouse.execute(
        "SELECT count(*) FROM pg_inherits WHERE inhparent = 'raw_xdr.incidents'::regclass"
    ).fetchone()
    # Wide enough to reach back past March 2019 from any plausible "now".
    warehouse.execute(partitions_sql("raw_xdr", "incidents", behind=240))
    after = warehouse.execute(
        "SELECT count(*) FROM pg_inherits WHERE inhparent = 'raw_xdr.incidents'::regclass"
    ).fetchone()
    assert before is not None and after is not None and after[0] > before[0]
    assert warehouse.execute("SELECT to_regclass('raw_xdr.incidents_2019_03')").fetchone() == (
        None,
    )
    assert warehouse.execute("SELECT to_regclass('raw_xdr.incidents_2019_04')").fetchone() != (
        None,
    )
    warehouse.rollback()


def test_partition_check_fails_only_when_next_month_is_missing(
    warehouse: psycopg.Connection,
) -> None:
    parents = [("raw_wazuh", "alerts"), (None, WAZUH.fact_table)]
    warehouse.execute(partition_check_sql(parents))
    nxt = warehouse.execute(
        "SELECT to_char(date_trunc('month', now()) + interval '1 month', 'YYYY_MM')"
    ).fetchone()
    assert nxt is not None
    warehouse.execute(f"DROP TABLE raw_wazuh.alerts_{nxt[0]}")
    with pytest.raises(psycopg.errors.RaiseException, match="raw_wazuh.alerts"):
        warehouse.execute(partition_check_sql(parents))
    warehouse.rollback()
