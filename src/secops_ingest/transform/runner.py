"""Transform execution.

Ordering is deliberate throughout:

  facts -> rollups -> coverage -> watermark

Coverage is recorded only after facts exist, and the watermark advances only
after coverage is recorded. A crash anywhere re-processes an overlap, which the
idempotent upsert absorbs, rather than marking a period covered that is not.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import Any

from psycopg import sql

from ..common import db
from .base import Target

log = logging.getLogger(__name__)


@dataclass
class TransformResult:
    status: str
    rows_upserted: int = 0
    days_touched: int = 0
    error: str | None = None


def _start(conn, target: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.transform_run (target, status) "
            "VALUES (%s, 'RUNNING') RETURNING run_id",
            (target,),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return int(run_id)


def _finish(conn, run_id: int, status: str, rows: int, days: int, error: str | None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE control.transform_run SET ended_at = now(), status = %s, "
            "rows_upserted = %s, days_touched = %s, error_summary = %s WHERE run_id = %s",
            (status, rows, days, (error or "")[:2000] or None, run_id),
        )
    conn.commit()


def _watermark(conn, target: str):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cursor_value FROM control.transform_watermark WHERE target = %s",
            (target,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def _advance(conn, target: str, value) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.transform_watermark (target, cursor_value, updated_at) "
            "VALUES (%s, %s, now()) ON CONFLICT (target) DO UPDATE "
            "SET cursor_value = EXCLUDED.cursor_value, updated_at = now()",
            (target, value),
        )
    conn.commit()


def execute(target: Target) -> TransformResult:
    with db.connect() as conn:
        run_id = _start(conn, target.name)
        try:
            since = _watermark(conn, target.name)

            # High-water mark captured BEFORE the upsert. Rows arriving mid-run
            # are simply picked up next time; advancing to a mark taken after
            # would skip them.
            raw = sql.SQL("SELECT max(_ingested_at) FROM {}").format(
                sql.Identifier(*target.raw_table.split("."))
            )
            with conn.cursor() as cur:
                cur.execute(raw)
                new_mark = cur.fetchone()[0]

            if new_mark is None or (since is not None and new_mark <= since):
                log.info("target=%s nothing new since %s", target.name, since)
                _finish(conn, run_id, "SUCCESS", 0, 0, None)
                return TransformResult("SUCCESS")

            with conn.cursor() as cur:
                cur.execute(target.upsert_sql, {"since": since})
                rows = cur.rowcount

            days = _affected_days(conn, target, since)
            if target.rollup_sql and days:
                _rebuild_rollups(conn, target, days)
            _record_coverage(conn, target, days)

            conn.commit()
            _advance(conn, target.name, new_mark)
            _finish(conn, run_id, "SUCCESS", rows, len(days), None)
            log.info("target=%s rows=%s days=%s", target.name, rows, len(days))
            return TransformResult("SUCCESS", rows, len(days))

        except Exception as exc:
            log.exception("target=%s run=%s failed", target.name, run_id)
            try:
                conn.rollback()
            except Exception:                      # pragma: no cover - defensive
                log.warning("rollback failed while handling a transform failure")
            try:
                _finish(conn, run_id, "FAILED", 0, 0, f"{type(exc).__name__}: {exc}")
            except Exception:
                log.exception("could not record FAILED for transform run=%s", run_id)
            raise


def _affected_days(conn, target: Target, since) -> list[date]:
    """Days touched by THIS run, derived from raw rows newer than the watermark.

    Deliberately not a scan of the fact table: that would return every day the
    target has ever produced, so a single new record would trigger a rebuild of
    every rollup in the table.
    """
    stmt = sql.SQL(
        # Cast for the same reason as in targets.py: a bare parameter inside
        # IS NULL has no type context and PostgreSQL refuses it.
        "SELECT DISTINCT _event_time::date AS d FROM {raw} "
        "WHERE %(since)s::timestamptz IS NULL "
        "   OR _ingested_at > %(since)s::timestamptz ORDER BY d"
    ).format(raw=sql.Identifier(*target.raw_table.split(".")))
    with conn.cursor() as cur:
        cur.execute(stmt, {"since": since})
        return [r[0] for r in cur.fetchall()]


def _rebuild_rollups(conn, target: Target, days: list[date]) -> None:
    """Recompute whole days from FACTS. Never increment.

    Incrementing double-counts on any retry. The day is cleared and rebuilt in
    one transaction so a dashboard never sees it briefly absent, and stale
    dimension combinations that no longer have rows disappear.
    """
    delete = sql.SQL("DELETE FROM {} WHERE day = ANY(%(days)s)").format(
        sql.Identifier(target.rollup_table)
    )
    with conn.cursor() as cur:
        cur.execute(delete, {"days": days})
        cur.execute(target.rollup_sql, {"days": days})


def _record_coverage(conn, target: Target, days: list[date]) -> None:
    """Prove a period's reporting rows exist, so raw expiry can be gated on it."""
    if not days:
        return
    months = sorted({d.replace(day=1) for d in days})
    stmt = sql.SQL(
        "INSERT INTO control.transform_coverage (target, period, fact_rows) "
        "SELECT %(target)s, date_trunc('month', {date_expr})::date, count(*) "
        "FROM {fact} WHERE date_trunc('month', {date_expr})::date = ANY(%(months)s) "
        "GROUP BY 2 "
        "ON CONFLICT (target, period) DO UPDATE "
        "SET fact_rows = EXCLUDED.fact_rows, completed_at = now()"
    ).format(
        fact=sql.Identifier(target.fact_table),
        date_expr=sql.SQL(target.fact_date_expr),
    )
    with conn.cursor() as cur:
        cur.execute(stmt, {"target": target.name, "months": months})
