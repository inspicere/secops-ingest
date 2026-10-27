"""The raw/mart drift check, at unit level.

A fake cursor answers pg_attribute per table; tests/schema/
test_grants_integration.py runs the check against a real server.
"""

from __future__ import annotations

import pytest

from secops_ingest.common import schema_check
from secops_ingest.transform.base import Target
from secops_ingest.transform.targets import TARGETS

THINGS = Target(
    name="vendor_things",
    raw_table="raw_vendor.things",
    fact_table="mart_fact_vendor_things",
    fact_date_expr="seen_at",
    upsert_sql="INSERT INTO mart_fact_vendor_things SELECT %(since)s::timestamptz",
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_vendor_things (
            thing_id   text        NOT NULL,
            seen_at    timestamptz NOT NULL,
            colour     text,
            PRIMARY KEY (thing_id, seen_at)
        ) PARTITION BY RANGE (seen_at);
        -- added in a later release; this line is the migration
        ALTER TABLE mart_fact_vendor_things ADD COLUMN IF NOT EXISTS weight numeric;
    """,
)

RAW_COLUMNS = {"source_id", "payload", "_event_time", "_ingested_at", "_source_run_id"}


class _Cursor:
    def __init__(self, tables: dict[str, set[str]]) -> None:
        self._tables = tables
        self._rows: list[tuple[str]] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, statement: str, params: tuple[str]) -> None:
        self._rows = [(c,) for c in sorted(self._tables.get(params[0], set()))]

    def fetchall(self) -> list[tuple[str]]:
        return self._rows


class _Conn:
    def __init__(self, tables: dict[str, set[str]]) -> None:
        self._tables = tables

    def cursor(self) -> _Cursor:
        return _Cursor(self._tables)


def test_every_shipped_target_parses_with_real_columns() -> None:
    columns, _ = schema_check.expected_target_columns(TARGETS.values())
    for target in TARGETS.values():
        assert set(columns[target.raw_table]) == RAW_COLUMNS
        if target.fact_ddl:
            assert columns[target.fact_table], target.name
            assert "PRIMARY" not in columns[target.fact_table]
        if target.rollup_ddl and target.rollup_table:
            assert columns[target.rollup_table], target.name


def test_alter_add_column_counts_as_expected_and_as_migrated() -> None:
    columns, migrated = schema_check.expected_target_columns([THINGS])
    assert columns["mart_fact_vendor_things"] == ["thing_id", "seen_at", "colour", "weight"]
    assert migrated["mart_fact_vendor_things"] == {"weight"}


def test_current_tables_pass() -> None:
    conn = _Conn({
        "raw_vendor.things": RAW_COLUMNS,
        "mart_fact_vendor_things": {"thing_id", "seen_at", "colour", "weight", "extra"},
    })
    schema_check.verify_target_schema(conn, [THINGS])


def test_a_migrated_column_points_at_reapplying_the_ddl() -> None:
    conn = _Conn({
        "raw_vendor.things": RAW_COLUMNS,
        "mart_fact_vendor_things": {"thing_id", "seen_at", "colour"},
    })
    with pytest.raises(schema_check.TargetSchemaDrift) as excinfo:
        schema_check.verify_target_schema(conn, [THINGS])
    message = str(excinfo.value)
    assert "mart_fact_vendor_things is missing column(s): weight" in message
    assert "python -m secops_ingest.schema" in message
    assert "No migration ships" not in message


def test_an_unmigrated_column_is_called_a_package_bug() -> None:
    """Re-applying CREATE TABLE IF NOT EXISTS cannot add it, so saying
    "re-apply the DDL" would send the operator round in a circle."""
    conn = _Conn({
        "raw_vendor.things": RAW_COLUMNS,
        "mart_fact_vendor_things": {"thing_id", "seen_at", "weight"},
    })
    with pytest.raises(schema_check.TargetSchemaDrift) as excinfo:
        schema_check.verify_target_schema(conn, [THINGS])
    assert "No migration ships for mart_fact_vendor_things (colour)" in str(excinfo.value)


def test_a_missing_table_is_named() -> None:
    conn = _Conn({"mart_fact_vendor_things": {"thing_id", "seen_at", "colour", "weight"}})
    with pytest.raises(schema_check.TargetSchemaDrift, match="raw_vendor.things does not exist"):
        schema_check.verify_target_schema(conn, [THINGS])


def test_unreadable_target_ddl_is_a_package_bug_not_drift() -> None:
    odd = Target(
        name="odd",
        raw_table="raw_vendor.odd",
        fact_table="mart_fact_odd",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_odd SELECT %(since)s::timestamptz",
        fact_ddl="CREATE TABLE mart_fact_odd AS SELECT 1",
    )
    with pytest.raises(RuntimeError, match="could not read the columns of mart_fact_odd"):
        schema_check.expected_target_columns([odd])
