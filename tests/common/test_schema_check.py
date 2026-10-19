"""The control-schema drift check, at unit level.

A fake cursor proves the message is assembled as intended; it proves nothing
about PostgreSQL. tests/schema/test_schema_drift_integration.py runs the same
check against a real server -- that file is the proof this works.
"""

from __future__ import annotations

import pytest

from secops_ingest.common import schema_check
from secops_ingest.schema import control_sql

# The full expectation, derived from control_sql(). Pinned here so a DDL edit
# that breaks the derivation (or silently stops mentioning a column) fails
# loudly in tests instead of misreporting at a deployment.
EXPECTED = {
    "ingest_run": [
        "run_id", "source", "started_at", "ended_at", "status", "posture",
        "rows_read", "rows_written", "error_summary",
    ],
    "ingest_watermark": ["source", "cursor_value", "cursor_type", "updated_at"],
    "transform_run": [
        "run_id", "target", "started_at", "ended_at", "status", "posture",
        "rows_upserted", "days_touched", "error_summary",
    ],
    "transform_watermark": ["target", "cursor_value", "updated_at"],
    "transform_coverage": ["target", "period", "fact_rows", "completed_at"],
    "pack": ["name", "version", "state", "enabled_at", "disabled_at"],
}


class _Cursor:
    def __init__(self, rows: list[tuple[str, str]]) -> None:
        self._rows = rows

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, statement: str) -> None:
        pass

    def fetchall(self) -> list[tuple[str, str]]:
        return self._rows


class _Conn:
    """Stand-in for a psycopg connection: cursor() answers fixed rows."""

    def __init__(self, rows: list[tuple[str, str]]) -> None:
        self._rows = rows

    def cursor(self) -> _Cursor:
        return _Cursor(self._rows)


def test_expectation_is_derived_from_control_sql() -> None:
    assert schema_check.expected_control_columns() == EXPECTED


def test_posture_is_expected_on_both_run_tables() -> None:
    expected = schema_check.expected_control_columns()
    assert "posture" in expected["ingest_run"]
    assert "posture" in expected["transform_run"]


def test_derivation_failure_is_a_loud_bug_not_a_wrong_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(schema_check, "control_sql", lambda: "-- no ddl here")
    with pytest.raises(RuntimeError, match="could not derive"):
        schema_check.expected_control_columns()


def test_a_complete_schema_passes() -> None:
    rows = [(t, c) for t, cols in EXPECTED.items() for c in cols]
    schema_check.verify_control_schema(_Conn(rows))


def test_extra_columns_and_tables_are_fine() -> None:
    # The warehouse may legitimately be ahead (hand-added columns, other tools'
    # tables in the same schema). Only what the package expects is checked.
    rows = [(t, c) for t, cols in EXPECTED.items() for c in cols]
    rows.append(("ingest_run", "operator_note"))
    rows.append(("something_else", "id"))
    schema_check.verify_control_schema(_Conn(rows))


def test_a_missing_column_names_table_column_and_remedy() -> None:
    rows = [(t, c) for t, cols in EXPECTED.items() for c in cols
            if not (t == "ingest_run" and c == "posture")]

    with pytest.raises(schema_check.ControlSchemaDrift) as excinfo:
        schema_check.verify_control_schema(_Conn(rows))

    message = str(excinfo.value)
    assert "control.ingest_run" in message
    assert "posture" in message
    assert "python -m secops_ingest.schema" in message
    assert "schema owner" in message
    # One line: log scrapers and pages should carry the whole diagnosis.
    assert "\n" not in message


def test_every_missing_column_is_listed() -> None:
    rows = [(t, c) for t, cols in EXPECTED.items() for c in cols
            if not (t == "transform_run" and c in ("posture", "days_touched"))]

    with pytest.raises(schema_check.ControlSchemaDrift) as excinfo:
        schema_check.verify_control_schema(_Conn(rows))

    message = str(excinfo.value)
    assert "control.transform_run" in message
    assert "posture, days_touched" in message


def test_a_missing_table_is_named_not_misreported_as_columns() -> None:
    rows = [(t, c) for t, cols in EXPECTED.items() for c in cols if t != "pack"]

    with pytest.raises(schema_check.ControlSchemaDrift) as excinfo:
        schema_check.verify_control_schema(_Conn(rows))

    assert "control.pack does not exist" in str(excinfo.value)


def test_every_control_table_is_checked() -> None:
    # Whole schema absent: every expected table must appear in the report.
    with pytest.raises(schema_check.ControlSchemaDrift) as excinfo:
        schema_check.verify_control_schema(_Conn([]))

    message = str(excinfo.value)
    for table in EXPECTED:
        assert f"control.{table}" in message


def test_control_sql_still_parses_after_any_edit() -> None:
    # Guard against the DDL drifting into a shape the parser silently
    # mis-reads: the derivation must account for every CREATE TABLE in it.
    creates = [
        line for line in control_sql().splitlines()
        if line.startswith("CREATE TABLE IF NOT EXISTS control.")
    ]
    assert len(creates) == len(EXPECTED)


def test_exception_carries_no_traceback_prone_chaining() -> None:
    rows: list[tuple[str, str]] = []
    try:
        schema_check.verify_control_schema(_Conn(rows))
    except schema_check.ControlSchemaDrift as exc:
        assert exc.__cause__ is None
        assert exc.__context__ is None
    else:  # pragma: no cover - the raise above is the point
        pytest.fail("ControlSchemaDrift was not raised")
