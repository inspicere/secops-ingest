"""upsert_many: a re-landed record that changed must look new to the transforms.

THE BUG THIS PINS (found by the transform side, reproduced against PostgreSQL
16). `_ingested_at` is a column DEFAULT, so ON CONFLICT DO UPDATE left it at
the FIRST landing. Every transform selects `_ingested_at > watermark`, so a
DefectDojo finding mitigated after it first landed, an XSOAR incident closed
later, a KSAT enrollment that progressed -- none reached a mart. Rows landed,
transforms reported SUCCESS, the marts kept the first-seen state.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import db  # noqa: E402


class _Conn:
    def __init__(self) -> None:
        self.sql: list[str] = []

    def cursor(self) -> _Conn:
        return self

    def __enter__(self) -> _Conn:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def executemany(self, stmt: Any, rows: Any) -> None:
        self.sql.append(stmt.as_string(None))

    def commit(self) -> None:
        return None


def _rendered(**kw: Any) -> str:
    conn = _Conn()
    db.upsert_many(conn, "raw_defectdojo.findings",  # type: ignore[arg-type]
                   [("1", "{}", "2026-01-01", 7)], **kw)
    return conn.sql[0]


def test_a_changed_payload_moves_ingested_at() -> None:
    sql = _rendered()
    assert "AS t" in sql
    assert ("_ingested_at = CASE WHEN t.payload IS DISTINCT FROM EXCLUDED.payload "
            "THEN now() ELSE t._ingested_at END") in sql


def test_an_unchanged_payload_keeps_it_so_a_full_reread_does_not_churn() -> None:
    # The ELSE branch: KSAT re-reads everything every run, and Wazuh overlaps
    # fifteen minutes; neither should push unchanged rows through a transform.
    assert "ELSE t._ingested_at" in _rendered()


def test_a_caller_landing_ingested_at_itself_is_left_alone() -> None:
    sql = _rendered(columns=("source_id", "payload", "_event_time", "_ingested_at"))
    assert "CASE WHEN" not in sql
    assert '"_ingested_at" = EXCLUDED."_ingested_at"' in sql
