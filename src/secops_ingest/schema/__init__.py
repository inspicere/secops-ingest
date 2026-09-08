"""Warehouse DDL.

Emits the SQL for the three layers this package assumes:

    raw_*     landing tables, monthly range partitions, JSONB payload
    control   run history, watermarks, and the coverage ledger
    mart_*    reporting facts and rollups (declared per target, see transform)

Every function returns SQL as text rather than executing it. That keeps the
schema usable from psql, Ansible, Flyway, a migration tool, or a human reading
it, instead of only from this package -- and it means nothing here needs a
database driver.

    python -m secops_ingest.schema --source wazuh --source defectdojo | psql "$DSN"
"""

from __future__ import annotations

import re

__all__ = [
    "InvalidIdentifier",
    "control_sql",
    "mart_partition_sql",
    "partitions_sql",
    "raw_table_sql",
    "validate_identifier",
]

#: Schema and table names arrive from configuration, and the partition DDL below
#: has to interpolate them into a DO block where bind parameters are unavailable.
#: Restricting the character set is what makes that interpolation safe.
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class InvalidIdentifier(ValueError):
    """A schema or table name is not a plain lowercase SQL identifier."""


def validate_identifier(name: str) -> str:
    if not isinstance(name, str) or not _IDENT.match(name):
        raise InvalidIdentifier(f"not a valid SQL identifier: {name!r}")
    return name


CONTROL_SQL = """\
-- Control schema: bookkeeping that outlives any single run.
CREATE SCHEMA IF NOT EXISTS control;

-- One row per ingest attempt. Retained so a gap in a dashboard can be traced to
-- a specific failed run rather than guessed at.
CREATE TABLE IF NOT EXISTS control.ingest_run (
    run_id        bigserial PRIMARY KEY,
    source        text        NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    status        text        NOT NULL DEFAULT 'RUNNING'
                  CHECK (status IN ('RUNNING','SUCCESS','FAILED')),
    rows_read     integer,
    rows_written  integer,
    error_summary text
);
CREATE INDEX IF NOT EXISTS ingest_run_source_started_idx
    ON control.ingest_run (source, started_at DESC);

-- Resumption point per source. cursor_value is text because sources disagree
-- about what a cursor is: an ISO timestamp, an opaque page token, an epoch.
CREATE TABLE IF NOT EXISTS control.ingest_watermark (
    source       text PRIMARY KEY,
    cursor_value text,
    cursor_type  text,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control.transform_run (
    run_id        bigserial PRIMARY KEY,
    target        text        NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    status        text        NOT NULL DEFAULT 'RUNNING'
                  CHECK (status IN ('RUNNING','SUCCESS','FAILED')),
    rows_upserted integer,
    days_touched  integer,
    error_summary text
);
CREATE INDEX IF NOT EXISTS transform_run_target_started_idx
    ON control.transform_run (target, started_at DESC);

CREATE TABLE IF NOT EXISTS control.transform_watermark (
    target       text PRIMARY KEY,
    cursor_value timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- THE COVERAGE LEDGER IS WHAT MAKES RAW EXPIRY SAFE.
--
-- Raw is a bounded re-derivation buffer; the reporting layer is what is kept.
-- Dropping a raw partition is therefore irreversible, and must never happen on
-- the assumption that the transform ran. Nothing may drop a period's partition
-- without a positive row here recording that the period's reporting rows exist.
--
-- Deleting a row from this table re-arms the guard for that period. It is the
-- one table where an accidental DELETE fails safe.
CREATE TABLE IF NOT EXISTS control.transform_coverage (
    target       text   NOT NULL,
    period       date   NOT NULL,
    fact_rows    bigint NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (target, period)
);
"""


def control_sql() -> str:
    """DDL for the control schema. Idempotent."""
    return CONTROL_SQL


def raw_table_sql(schema: str, table: str, *, gin_index: bool = False) -> str:
    """DDL for one partitioned raw landing table.

    `_event_time` MUST be populated from an immutable field -- the record's
    creation time -- and never from the field the watermark uses. Sources that
    mutate records (vulnerability findings, ticket-shaped data) watermark on the
    modification time so that state changes are re-read; partitioning on that
    would move a row between partitions every time somebody touched it.

    Partitioning forces the partition key into the primary key, which is why
    every connector's upsert conflicts on (source_id, _event_time).

    Args:
        gin_index: index the JSONB payload. Off by default -- a GIN index per
            raw table is write-amplifying and only earns its keep if raw
            payloads are queried ad hoc. Dashboards read the mart layer.
    """
    validate_identifier(schema)
    validate_identifier(table)
    sql = f"""\
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.{table} (
    source_id      text        NOT NULL,
    payload        jsonb       NOT NULL,
    _event_time    timestamptz NOT NULL,
    _ingested_at   timestamptz NOT NULL DEFAULT now(),
    _source_run_id bigint,
    PRIMARY KEY (source_id, _event_time)
) PARTITION BY RANGE (_event_time);

-- The transform selects on _ingested_at, not _event_time: it asks "what landed
-- since my watermark", which for a mutating source includes rows whose event
-- time is months old.
CREATE INDEX IF NOT EXISTS {table}_ingested_at_idx
    ON {schema}.{table} (_ingested_at);
"""
    if gin_index:
        sql += (
            f"\nCREATE INDEX IF NOT EXISTS {table}_payload_gin\n"
            f"    ON {schema}.{table} USING gin (payload);\n"
        )
    return sql


def _partition_do_block(qualified: str, prefix: str, behind: int, ahead: int) -> str:
    """A DO block creating monthly partitions across a window.

    THE MONTH ARITHMETIC IS POSTGRESQL'S, DELIBERATELY. Adding a fixed "average
    month" of seconds to a date in application code drifts, and eventually skips
    or duplicates a month -- which surfaces as inserts failing at midnight on the
    first. generate_series over interval '1 month' cannot drift.
    """
    return f"""\
DO $do$
DECLARE
    m date;
BEGIN
    FOR m IN
        SELECT generate_series(
            date_trunc('month', now()) - make_interval(months => {behind}),
            date_trunc('month', now()) + make_interval(months => {ahead}),
            interval '1 month')::date
    LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF {qualified} '
            'FOR VALUES FROM (%L) TO (%L)',
            '{prefix}_' || to_char(m, 'YYYY_MM'),
            m,
            (m + interval '1 month')::date);
    END LOOP;
END
$do$;
"""


def partitions_sql(schema: str, table: str, *, behind: int = 1, ahead: int = 3) -> str:
    """Create monthly partitions for a raw table across a rolling window.

    A MISSING PARTITION MAKES INSERTS FAIL -- at midnight on the first of a
    month, with no prior warning. Run this on every deploy so the lookahead is
    maintained rather than assumed.
    """
    validate_identifier(schema)
    validate_identifier(table)
    if ahead < 1:
        raise ValueError("ahead must be >= 1, or the current month is the last one created")
    return _partition_do_block(f"{schema}.{table}", table, behind, ahead)


def mart_partition_sql(table: str, *, behind: int = 1, ahead: int = 3) -> str:
    """Create monthly partitions for a partitioned mart table.

    Mart tables are partitioned so roll-off is a partition DROP. Rolling a month
    off an unpartitioned seven-year table means DELETEing a month of rows, which
    leaves bloat and vacuum work behind every month, forever.
    """
    validate_identifier(table)
    if ahead < 1:
        raise ValueError("ahead must be >= 1, or the current month is the last one created")
    return _partition_do_block(table, table, behind, ahead)
