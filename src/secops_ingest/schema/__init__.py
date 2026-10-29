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
from collections.abc import Sequence

from ..transform.base import Target

__all__ = [
    "InvalidIdentifier",
    "control_sql",
    "control_tables",
    "ddl_for_targets",
    "grants_sql",
    "mart_partition_sql",
    "partition_check_sql",
    "partition_health_sql",
    "partitions_sql",
    "raw_table_sql",
    "source_freshness_sql",
    "source_state_sql",
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
    -- Which secret posture produced this row. Nullable: rows predating the
    -- column are not retroactively 'assured', and claiming they were would be
    -- the opposite of what this column is for.
    posture       text,
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
    -- Which secret posture produced this row. Nullable: rows predating the
    -- column are not retroactively 'assured', and claiming they were would be
    -- the opposite of what this column is for.
    posture       text,
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

-- Which packs are installed and whether they may run.
--
-- The row outlives the distribution deliberately. `pip uninstall` of a pack
-- leaves this row behind, and `pack list` reports the result as "enabled but
-- not installed" -- a real state, and the one the DefectDojo incident looked
-- like from the outside: a host pinned to a ref while running a copy that
-- predated the connector, failing as "unknown source" and blaming the
-- connector rather than the install.
--
-- `version` is what makes a silent no-op upgrade visible. `pip install
-- --upgrade` can resolve to nothing, exit 0, and report success; `pack list`
-- compares this column to the installed pack's version and marks any
-- difference. That only works for versions that actually move between
-- releases -- see __version__ in secops_ingest/__init__.py.
CREATE TABLE IF NOT EXISTS control.pack (
    name        text PRIMARY KEY,
    version     text        NOT NULL,
    state       text        NOT NULL
                CHECK (state IN ('ENABLED','DISABLED')),
    enabled_at  timestamptz,
    disabled_at timestamptz
);

-- Why a source is not running, when that was somebody's decision (audit V-18).
--
-- A pack DISABLED, or a source the deployment holds out, used to leave no
-- trace: its timer is simply absent, nothing writes control.ingest_run, and a
-- freshness card could not tell "held out on purpose" from "broken". One row
-- per (source, origin), because the two origins are independent decisions --
-- a deployment releasing its hold-out must not re-enable a pack an operator
-- disabled, and `packs enable` must not cancel a deployment's hold-out:
--
--   origin 'pack'    written by `packs disable` / `packs enable`, as the
--                    schema owner, for every source of the pack
--   origin 'deploy'  written by `python -m secops_ingest.holdout` through
--                    control.hold_out_source() and control.release_source(),
--                    which are the only way a worker role can write here
--
-- A release sets the row back to ACTIVE instead of deleting it, so who
-- released the source and when stays visible. control.source_freshness reads
-- this table beside the run ledgers, so a dashboard card is one SELECT.
CREATE TABLE IF NOT EXISTS control.source_state (
    source     text        NOT NULL,
    origin     text        NOT NULL CHECK (origin IN ('pack','deploy')),
    state      text        NOT NULL
               CHECK (state IN ('ACTIVE','DISABLED','HELD_OUT')),
    reason     text,
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by text        NOT NULL DEFAULT current_user,
    -- One line on purpose: schema_check reads each body line's first word as
    -- a column name unless it is a constraint keyword.
    CHECK (state = 'ACTIVE' OR state = CASE origin WHEN 'pack' THEN 'DISABLED' ELSE 'HELD_OUT' END),
    PRIMARY KEY (source, origin)
);

-- Migrations for tables created by an earlier version. CREATE TABLE IF NOT
-- EXISTS leaves an existing table untouched, so without these an upgraded
-- host fails every ingest and transform run with an undefined column until
-- someone remembers to apply the change by hand.
ALTER TABLE control.ingest_run ADD COLUMN IF NOT EXISTS posture text;
ALTER TABLE control.transform_run ADD COLUMN IF NOT EXISTS posture text;
"""


def control_sql() -> str:
    """DDL for the control schema. Idempotent."""
    return CONTROL_SQL


_CONTROL_TABLE = re.compile(
    r"^CREATE TABLE IF NOT EXISTS control\.([a-z_][a-z0-9_]*)", re.MULTILINE
)


def control_tables() -> list[str]:
    """Every table control_sql() creates, in creation order.

    Derived rather than listed, for the reason schema_check gives: grants that
    name tables from a second list would silently stop covering a table added
    to the first.
    """
    return _CONTROL_TABLE.findall(CONTROL_SQL)


PARTITION_HEALTH_SQL = """\
-- One row per partitioned raw_* or mart_* parent: how many rows sit in its
-- DEFAULT partition, and how far ahead its monthly partitions reach.
--
-- This is the "running dim" signal for partitioning. A DEFAULT partition keeps
-- an out-of-window row from failing its whole run, but rows there are outside
-- the monthly lifecycle -- never expired by a partition DROP -- so a monitor
-- should alert on default_rows > 0, and on covered_until falling within a
-- month of now(), which means the partition timer has stopped.
--
-- SECURITY DEFINER so a monitoring role can call it without being able to
-- read a single raw row: it returns counts and dates, nothing else. The pinned
-- search_path is what makes a definer function safe to expose.
-- default_rows is NULL when the parent has no DEFAULT partition at all.
CREATE OR REPLACE FUNCTION control.partition_health()
RETURNS TABLE (parent text, default_rows bigint, covered_until timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.oid, n.nspname, c.relname, p.partdefid
        FROM pg_partitioned_table p
        JOIN pg_class c ON c.oid = p.partrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname LIKE 'raw\\_%' OR c.relname LIKE 'mart\\_%'
        ORDER BY 2, 3
    LOOP
        parent := format('%I.%I', r.nspname, r.relname);
        default_rows := NULL;
        IF r.partdefid <> 0 THEN
            EXECUTE format('SELECT count(*) FROM %s', r.partdefid::regclass)
                INTO default_rows;
        END IF;
        SELECT max(substring(pg_get_expr(k.relpartbound, k.oid)
                             FROM 'TO \\(''([^'']+)''\\)')::timestamptz)
            INTO covered_until
            FROM pg_inherits i
            JOIN pg_class k ON k.oid = i.inhrelid
            WHERE i.inhparent = r.oid AND k.oid <> r.partdefid;
        RETURN NEXT;
    END LOOP;
END
$fn$;
REVOKE ALL ON FUNCTION control.partition_health() FROM PUBLIC;
"""


def partition_health_sql() -> str:
    """DDL for `control.partition_health()`. Idempotent.

    Kept out of control_sql() on purpose. CREATE OR REPLACE FUNCTION requires
    being the function's owner, and control_sql() is also applied by
    `pack enable` under whatever role that DSN names; putting the function
    there would make every enable by a non-owner fail on a statement that has
    nothing to do with the pack.
    """
    return PARTITION_HEALTH_SQL


def partition_check_sql(parents: Sequence[tuple[str | None, str]]) -> str:
    """A statement that FAILS unless every parent has next month's partition.

    `parents` is (schema, table) pairs, schema None for an unqualified mart
    table. Emitted after the partition blocks by `--partitions-only`, so a timer
    run that could not move the window exits non-zero (under psql's
    ON_ERROR_STOP) instead of logging a WARNING nobody reads. It is a separate
    statement from the blocks before it, so under autocommit whatever they did
    create is kept.
    """
    checks: list[str] = []
    for schema, table in parents:
        validate_identifier(table)
        if schema is not None:
            validate_identifier(schema)
            name = f"format('%I.%I', '{schema}', '{table}_' || nxt)"
            label = f"{schema}.{table}"
        else:
            name = f"format('%I', '{table}_' || nxt)"
            label = table
        checks.append(
            f"    IF to_regclass({name}) IS NULL THEN\n"
            f"        missing := array_append(missing, '{label}');\n"
            f"    END IF;"
        )
    body = "\n".join(checks)
    return f"""\
DO $do$
DECLARE
    nxt text := to_char(date_trunc('month', now()) + interval '1 month', 'YYYY_MM');
    missing text[] := '{{}}';
BEGIN
{body}
    IF cardinality(missing) > 0 THEN
        RAISE EXCEPTION 'no partition for % on: %', nxt, array_to_string(missing, ', ')
            USING HINT = 'rows for that month will land in DEFAULT; '
                         'see control.partition_health()';
    END IF;
END
$do$;
"""


SOURCE_STATE_SQL = """\
-- The only way a worker role can write control.source_state: record that the
-- deployment holds a source out, or release a hold-out it recorded itself.
--
-- SECURITY DEFINER rather than a grant on the table, because a grant cannot
-- say which ROWS. An ingest role with INSERT/UPDATE on the table could also
-- clear a pack's DISABLED row -- the forgery the per-table control grants exist
-- to prevent. These functions only ever touch origin 'deploy', and they record
-- session_user, the login that called them (current_user inside a definer
-- function is the owner), so a row says truthfully who held the source out.
-- The pinned search_path is what makes a definer function safe to expose.
--
-- Both return whether anything changed. A converge re-asserts the same
-- hold-out on every run, and it should report "ok", not "changed", while
-- changed_at keeps meaning the moment the state actually changed.
--
-- A hold-out another login recorded is taken over rather than refused: the
-- source stays held out either way. Release is "own rows only": a deployment
-- on one host must not lift a hold-out recorded by another host's login. The
-- schema owner can still change any row directly.
CREATE OR REPLACE FUNCTION control.hold_out_source(p_source text, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    n integer;
BEGIN
    IF p_source IS NULL OR p_source !~ '^[a-z_][a-z0-9_]{0,62}$' THEN
        RAISE EXCEPTION 'not a source name: %', p_source
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A hold-out with no reason is the silence this table exists to end.
    IF p_reason IS NULL OR btrim(p_reason) = '' OR length(p_reason) > 500 THEN
        RAISE EXCEPTION 'holding out %: a reason of 1 to 500 characters is required', p_source
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO control.source_state AS s
        (source, origin, state, reason, changed_at, changed_by)
    VALUES (p_source, 'deploy', 'HELD_OUT', p_reason, now(), session_user)
    ON CONFLICT (source, origin) DO UPDATE
        SET state = 'HELD_OUT', reason = EXCLUDED.reason,
            changed_at = now(), changed_by = session_user
        WHERE s.state <> 'HELD_OUT' OR s.reason IS DISTINCT FROM EXCLUDED.reason
           OR s.changed_by <> session_user;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n > 0;
END
$fn$;
REVOKE ALL ON FUNCTION control.hold_out_source(text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION control.release_source(p_source text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    holder text;
    current_state text;
BEGIN
    SELECT changed_by, state INTO holder, current_state
        FROM control.source_state
        WHERE source = p_source AND origin = 'deploy'
        FOR UPDATE;
    IF NOT FOUND OR current_state <> 'HELD_OUT' THEN
        RETURN false;
    END IF;
    IF holder <> session_user THEN
        RAISE EXCEPTION 'source % is held out by %, not by %; only that login, or '
            'the schema owner directly, can release it', p_source, holder, session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE control.source_state
        SET state = 'ACTIVE', reason = NULL, changed_at = now(), changed_by = session_user
        WHERE source = p_source AND origin = 'deploy';
    RETURN true;
END
$fn$;
REVOKE ALL ON FUNCTION control.release_source(text) FROM PUBLIC;
"""

#: The definer functions SOURCE_STATE_SQL creates, by signature: what grants
#: name, and what the drift check looks for with to_regprocedure().
SOURCE_STATE_FUNCTIONS = (
    "control.hold_out_source(text, text)",
    "control.release_source(text)",
)


def source_state_sql() -> str:
    """DDL for the hold-out functions over `control.source_state`. Idempotent.

    Kept out of control_sql() for the reason partition_health_sql() is: CREATE
    OR REPLACE FUNCTION needs the function's owner, and `pack enable` applies
    control_sql() under whatever role its DSN names.
    """
    return SOURCE_STATE_SQL


#: The columns of control.source_freshness, in order. CREATE OR REPLACE VIEW
#: can only append columns, so this order is an interface: dashboards select
#: these names, and the drift check expects them.
SOURCE_FRESHNESS_COLUMNS = (
    "source", "pack", "state", "state_reason", "state_changed_at", "state_changed_by",
    "targets", "last_ingest_success", "last_transform_success", "never_succeeded",
    "as_of", "age",
)


def _sql_text(value: str | None) -> str:
    """A text literal for a name already checked by validate_identifier()."""
    return "NULL::text" if value is None else f"'{validate_identifier(value)}'::text"


def source_freshness_sql(sources: Sequence[tuple[str, str | None, Sequence[str]]]) -> str:
    """DDL for the `control.source_freshness` view. Idempotent.

    `sources` is (source, pack, targets reading the source's raw table), as the
    emitter derives it from the installed packs. The warehouse has no other way
    to know which targets derive from which source -- a source names a raw
    table only in its connector module -- so the mapping is written into the
    view, and regenerating the schema is what updates it. A source the mapping
    does not know (a private connector, say) still gets a row from the run
    ledger or from control.source_state, with no pack and no targets.

    FRESHNESS IS THE OLDER OF INGEST AND TRANSFORM SUCCESS. A transform that
    keeps succeeding over raw nobody refreshes reports SUCCESS with 0 rows, and
    an ingest that keeps succeeding into a transform that has stopped leaves the
    mart frozen; either way the data a reader sees is only as new as the older
    of the two. "Never" is NULL, and it is handled explicitly: PostgreSQL's
    least() ignores NULL, so least(ingest, never) would report the ingest time
    and hide a target that never succeeded. `never_succeeded` names what has no
    SUCCESS row at all, so a card can say which half is missing.

    `state` is DISABLED when the source's pack is (control.pack decides when the
    pack is known, since that is what the worker obeys; control.source_state's
    pack row otherwise), HELD_OUT when the deployment holds it out, else ACTIVE.
    """
    rows: list[str] = []
    for source, pack, targets in sources:
        reading: list[str | None] = [*sorted(targets)] or [None]
        for target in reading:
            rows.append(f"({_sql_text(source)}, {_sql_text(pack)}, {_sql_text(target)})")
    if rows:
        known = "    VALUES\n        " + ",\n        ".join(rows)
    else:
        known = "    SELECT NULL::text, NULL::text, NULL::text WHERE false"
    return f"""\
-- One row per source: how current its data is and whether it is held out on
-- purpose. A freshness card is `SELECT * FROM control.source_freshness WHERE
-- source = '...'`. The grants' SELECT ON ALL TABLES IN SCHEMA control covers
-- views too, so the read and monitor roles can query it with no new grant.
--
-- Columns may only be appended (CREATE OR REPLACE VIEW refuses anything else).
CREATE OR REPLACE VIEW control.source_freshness AS
WITH known (source, pack, target) AS (
{known}
),
ingest AS (
    SELECT source, max(ended_at) FILTER (WHERE status = 'SUCCESS') AS last_success
    FROM control.ingest_run GROUP BY source
),
transform AS (
    SELECT target, max(ended_at) FILTER (WHERE status = 'SUCCESS') AS last_success
    FROM control.transform_run GROUP BY target
),
sources AS (
    SELECT source FROM known
    UNION SELECT source FROM ingest
    UNION SELECT source FROM control.source_state
),
mapped AS (
    SELECT s.source,
           (SELECT min(k.pack) FROM known k WHERE k.source = s.source) AS pack,
           i.last_success AS last_ingest_success,
           coalesce(t.targets, '{{}}') AS targets,
           t.last_transform_success,
           coalesce(t.never, '{{}}') AS never_targets
    FROM sources s
    LEFT JOIN ingest i ON i.source = s.source
    LEFT JOIN LATERAL (
        SELECT array_agg(k.target ORDER BY k.target) AS targets,
               CASE WHEN bool_or(tr.last_success IS NULL) THEN NULL
                    ELSE min(tr.last_success) END AS last_transform_success,
               array_agg(k.target ORDER BY k.target)
                   FILTER (WHERE tr.last_success IS NULL) AS never
        FROM known k
        LEFT JOIN transform tr ON tr.target = k.target
        WHERE k.source = s.source AND k.target IS NOT NULL
    ) t ON true
),
held AS (
    SELECT m.*,
           sp.state AS pack_row_state, sp.reason AS pack_reason,
           sp.changed_at AS pack_changed_at, sp.changed_by AS pack_changed_by,
           sd.changed_at AS deploy_changed_at, sd.changed_by AS deploy_changed_by,
           sd.reason AS deploy_reason, cp.disabled_at AS pack_disabled_at,
           coalesce(CASE WHEN cp.state IS NOT NULL THEN cp.state = 'DISABLED'
                         ELSE sp.state = 'DISABLED' END, false) AS pack_disabled,
           coalesce(sd.state = 'HELD_OUT', false) AS held_out,
           (CASE WHEN m.last_ingest_success IS NULL THEN ARRAY['ingest'] ELSE '{{}}' END)
               || m.never_targets AS never_succeeded
    FROM mapped m
    LEFT JOIN control.pack cp ON cp.name = m.pack
    LEFT JOIN control.source_state sp ON sp.source = m.source AND sp.origin = 'pack'
    LEFT JOIN control.source_state sd ON sd.source = m.source AND sd.origin = 'deploy'
)
SELECT source,
       pack,
       CASE WHEN pack_disabled THEN 'DISABLED'
            WHEN held_out THEN 'HELD_OUT'
            ELSE 'ACTIVE' END AS state,
       CASE WHEN pack_disabled THEN
                coalesce(CASE WHEN pack_row_state = 'DISABLED' THEN pack_reason END,
                         'pack ' || pack || ' is DISABLED in control.pack')
            WHEN held_out THEN deploy_reason END AS state_reason,
       CASE WHEN pack_disabled THEN
                coalesce(CASE WHEN pack_row_state = 'DISABLED' THEN pack_changed_at END,
                         pack_disabled_at)
            WHEN held_out THEN deploy_changed_at
            ELSE greatest(pack_changed_at, deploy_changed_at) END AS state_changed_at,
       CASE WHEN pack_disabled THEN
                CASE WHEN pack_row_state = 'DISABLED' THEN pack_changed_by END
            WHEN held_out THEN deploy_changed_by
            WHEN deploy_changed_at IS NOT DISTINCT FROM
                 greatest(pack_changed_at, deploy_changed_at) THEN deploy_changed_by
            ELSE pack_changed_by END AS state_changed_by,
       targets,
       last_ingest_success,
       last_transform_success,
       never_succeeded,
       CASE WHEN cardinality(never_succeeded) > 0 THEN NULL
            WHEN cardinality(targets) = 0 THEN last_ingest_success
            ELSE least(last_ingest_success, last_transform_success) END AS as_of,
       now() - CASE WHEN cardinality(never_succeeded) > 0 THEN NULL
                    WHEN cardinality(targets) = 0 THEN last_ingest_success
                    ELSE least(last_ingest_success, last_transform_success) END AS age
FROM held;
"""


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


def _partition_do_block(
    qualified: str, prefix: str, behind: int, ahead: int, schema: str | None = None
) -> str:
    """A DO block creating a DEFAULT partition and monthly partitions across a window.

    THE MONTH ARITHMETIC IS POSTGRESQL'S, DELIBERATELY. Adding a fixed "average
    month" of seconds to a date in application code drifts, and eventually skips
    or duplicates a month -- which surfaces as inserts failing at midnight on the
    first. generate_series over interval '1 month' cannot drift.

    THE PARTITION NAME MUST BE SCHEMA-QUALIFIED when the parent is. An
    unqualified %I resolves against search_path, so partitions of
    raw_phisher.messages were being created as public.messages_2026_09 --
    attached to the right parent, in the wrong schema. They still worked, which
    is why it went unnoticed: pg_inherits reports the parent/child relationship
    regardless of where the child lives, so a count of partitions looked
    correct. What broke quietly was everything that reasons about schemas --
    ALTER DEFAULT PRIVILEGES IN SCHEMA raw_* no longer covered them, and the
    isolation between raw schemas was not real.

    THE DEFAULT PARTITION IS WHAT KEEPS ONE OLD RECORD FROM STOPPING A SOURCE.
    Mutating sources partition on an immutable creation date but re-read records
    by modification date, so an incident from 2024 touched today arrives with an
    `_event_time` no monthly partition covers. Without a DEFAULT the insert fails
    with "no partition of relation ... found for row", the run is FAILED, the
    watermark holds, and every later run re-reads the same record and fails the
    same way: the source is dark until someone writes DDL by hand. With one, the
    row lands and the source keeps moving. Rows in DEFAULT never expire with a
    monthly DROP, which is why `control.partition_health()` reports how many
    there are -- a non-zero count is the signal to look, not a failure.

    A month whose rows are already in DEFAULT cannot be created normally:
    PostgreSQL refuses a new partition whose range DEFAULT already holds rows for
    (check_violation). That month is skipped with a WARNING naming it, and every
    other month is still created -- one awkward month must not stop the window
    moving for all the others. In practice it only happens when the window is
    widened backwards over months that previously landed in DEFAULT.
    """
    if schema:
        target = "%I.%I"
        name_args = f"'{schema}',\n                '{prefix}_' || to_char(m, 'YYYY_MM'),"
        default_args = f"'{schema}', '{prefix}_default'"
    else:
        target = "%I"
        name_args = f"'{prefix}_' || to_char(m, 'YYYY_MM'),"
        default_args = f"'{prefix}_default'"

    return f"""\
DO $do$
DECLARE
    m date;
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS {target} PARTITION OF {qualified} DEFAULT',
        {default_args});
    FOR m IN
        SELECT generate_series(
            date_trunc('month', now()) - make_interval(months => {behind}),
            date_trunc('month', now()) + make_interval(months => {ahead}),
            interval '1 month')::date
    LOOP
        BEGIN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS {target} PARTITION OF {qualified} '
                'FOR VALUES FROM (%L) TO (%L)',
                {name_args}
                m,
                (m + interval '1 month')::date);
        EXCEPTION WHEN check_violation THEN
            RAISE WARNING '{qualified}: month % not created because its DEFAULT '
                'partition already holds rows for it; they stay in DEFAULT until '
                'moved by hand (%)', to_char(m, 'YYYY-MM'), SQLERRM;
        END;
    END LOOP;
END
$do$;
"""


def _check_partition_names(prefix: str) -> None:
    """The longest child name must still be a valid identifier.

    PostgreSQL truncates an over-long name with only a NOTICE, so a parent near
    the 63-byte limit would get partitions whose names collide with each other
    -- and the IF NOT EXISTS above would then silently skip months.
    """
    validate_identifier(f"{prefix}_default")


def partitions_sql(schema: str, table: str, *, behind: int = 1, ahead: int = 3) -> str:
    """Create a DEFAULT and monthly partitions for a raw table across a rolling window.

    A MISSING PARTITION USED TO MAKE INSERTS FAIL -- at midnight on the first of
    a month, with no prior warning. The DEFAULT partition now catches those rows
    instead, so a lapsed window dims (rows pile up in DEFAULT, and
    `control.partition_health()` says so) rather than going dark. The window
    still has to be kept moving: run this from a timer as well as on every
    deploy -- `python -m secops_ingest.schema --partitions-only` emits exactly
    these blocks for that.
    """
    validate_identifier(schema)
    validate_identifier(table)
    _check_partition_names(table)
    if ahead < 1:
        raise ValueError("ahead must be >= 1, or the current month is the last one created")
    return _partition_do_block(f"{schema}.{table}", table, behind, ahead, schema=schema)


def mart_partition_sql(table: str, *, behind: int = 1, ahead: int = 3) -> str:
    """Create monthly partitions for a partitioned mart table.

    Mart tables are partitioned so roll-off is a partition DROP. Rolling a month
    off an unpartitioned seven-year table means DELETEing a month of rows, which
    leaves bloat and vacuum work behind every month, forever.
    """
    validate_identifier(table)
    _check_partition_names(table)
    if ahead < 1:
        raise ValueError("ahead must be >= 1, or the current month is the last one created")
    return _partition_do_block(table, table, behind, ahead)


def ddl_for_targets(
    targets: Sequence[Target],
    *,
    behind: int = 1,
    ahead: int = 3,
    gin_index: bool = False,
) -> str:
    """DDL for a set of transform targets: raw table, partitions, facts, rollup.

    This is the one place that decides what a target's DDL looks like. The
    emitter (`schema/__main__.py`) and `pack enable` both call it, so they
    cannot drift into applying different DDL for the same target -- a drift
    that would only surface as a table present in one's output and absent from
    the other's.

    Raises:
        ValueError: a target's raw_table is not schema-qualified.
    """
    out: list[str] = []
    for t in targets:
        schema, _, table = t.raw_table.partition(".")
        if not table:
            raise ValueError(f"target {t.name}: raw_table {t.raw_table!r} is not schema-qualified")

        out.append(f"-- raw landing table\n{raw_table_sql(schema, table, gin_index=gin_index)}")
        out.append(
            f"-- monthly partitions for {t.raw_table}\n"
            + partitions_sql(schema, table, behind=behind, ahead=ahead)
        )

        if t.fact_ddl:
            out.append(f"-- reporting facts\n{t.fact_ddl.strip()}\n")
            # Only partition what declares itself partitioned; a DO block against
            # an unpartitioned table fails, and would fail on every deploy.
            if "PARTITION BY RANGE" in t.fact_ddl:
                out.append(
                    f"-- monthly partitions for {t.fact_table}\n"
                    + mart_partition_sql(t.fact_table, behind=behind, ahead=ahead)
                )

        if t.rollup_ddl:
            out.append(f"-- daily rollup\n{t.rollup_ddl.strip()}\n")

    return "\n".join(out)


def _default_privileges(
    schema: str, privileges: str, role: str, owner_role: str | None, *, revoke: bool = False
) -> list[str]:
    """ALTER DEFAULT PRIVILEGES for tables created later in `schema`.

    DEFAULT PRIVILEGES BELONG TO A CREATING ROLE. The plain form only covers
    tables later created by whoever runs this file; a table created by anyone
    else -- `pack enable` run as the schema owner, a partition made by hand --
    carries no grants, and the worker fails with "permission denied" on the
    first row of the new month. Naming the owner with FOR ROLE covers the role
    that actually creates them. Both are emitted, because the role applying the
    file creates partitions too.
    """
    verb = "REVOKE" if revoke else "GRANT"
    prep = "FROM" if revoke else "TO"
    lines = [
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
        f"{verb} {privileges} ON TABLES {prep} {role};"
    ]
    if owner_role:
        lines.append(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner_role} IN SCHEMA {schema} "
            f"{verb} {privileges} ON TABLES {prep} {role};"
        )
    return lines


#: Which control tables each worker writes; everything else in control it may
#: only read. control.pack is in neither list: only the schema owner may change
#: whether a pack runs.
_INGEST_WRITES = ("ingest_run", "ingest_watermark")
_TRANSFORM_WRITES = ("transform_run", "transform_watermark", "transform_coverage")


def _control_grants(role: str, writes: Sequence[str]) -> list[str]:
    """Read every control table; write only `writes`.

    READ ALL, WRITE OWN. Read access to the whole schema is required, not
    generous: the startup drift check reads information_schema.columns, which
    only lists columns of tables the role holds some privilege on, so a role
    that could not see control.transform_run would report it as missing and
    refuse to run.

    The REVOKEs are what make this hold on a warehouse that was converged with
    the old blanket grants (or hand grants), since a GRANT never takes anything
    away. They name only tables the role must NOT write -- revoking from its
    own tables and granting back would open a window, mid-converge, in which a
    running job's next INSERT fails. DELETE and TRUNCATE are never needed by
    either job, so they are revoked everywhere.
    """
    out = [
        f"GRANT USAGE ON SCHEMA control TO {role};",
        f"GRANT SELECT ON ALL TABLES IN SCHEMA control TO {role};",
    ]
    for table in control_tables():
        if table in writes:
            out.append(f"GRANT SELECT, INSERT, UPDATE ON control.{table} TO {role};")
            out.append(f"REVOKE DELETE, TRUNCATE ON control.{table} FROM {role};")
        else:
            out.append(
                f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.{table} FROM {role};"
            )
    # bigserial: INSERT alone is not enough. Only the run tables have one.
    for table in writes:
        if table.endswith("_run"):
            out.append(f"GRANT USAGE, SELECT ON SEQUENCE control.{table}_run_id_seq TO {role};")
    return out


def _hold_out_grants(role: str) -> list[str]:
    """EXECUTE on the hold-out functions: an ingest role's only write to
    control.source_state. The transform, read and monitor roles never get it --
    holding a source out is the deployment's decision, made where the ingest
    timers are."""
    return [f"GRANT EXECUTE ON FUNCTION {fn} TO {role};" for fn in SOURCE_STATE_FUNCTIONS]


def _parse_remote(
    remote_ingest: Sequence[tuple[str, str]], raw_schemas: Sequence[str]
) -> dict[str, str]:
    """{schema: role} for remote writers, refusing anything ambiguous."""
    by_schema: dict[str, str] = {}
    for role, schema in remote_ingest:
        validate_identifier(role)
        validate_identifier(schema)
        if schema not in raw_schemas:
            raise ValueError(
                f"remote ingest role {role}: {schema} is not one of the raw schemas "
                f"being emitted ({', '.join(raw_schemas) or '-'})"
            )
        if schema in by_schema and by_schema[schema] != role:
            raise ValueError(
                f"raw schema {schema} is given to two remote ingest roles: "
                f"{by_schema[schema]} and {role}"
            )
        by_schema[schema] = role
    return by_schema


def grants_sql(
    raw_schemas: list[str],
    mart_tables: list[str],
    *,
    ingest_role: str | None = None,
    transform_role: str | None = None,
    read_role: str | None = None,
    monitor_role: str | None = None,
    remote_ingest: Sequence[tuple[str, str]] = (),
    owner_role: str | None = None,
    partition_health: bool = False,
    source_state: bool = False,
    shared_keeps_remote: bool = False,
) -> str:
    """Privileges for the jobs that touch this schema.

    Roles are named rather than assumed, because role naming is a local
    convention and hardcoding one makes the package unusable anywhere else.
    Omit a role and its grants are simply not emitted.

    Args:
        ingest_role: lands raw records in every raw schema not given to a
            remote writer, and records its own runs.
        transform_role: reads every raw schema, writes the mart, records its
            own runs and coverage.
        read_role: reporting. The mart, plus read-only control, so a
            pipeline-health dashboard can be built on the same connection.
        monitor_role: external monitoring. Read-only control and
            partition_health(), and nothing else -- no raw, no mart.
            Both read control.source_freshness through the same SELECT.
        remote_ingest: (role, schema) pairs. Each role writes only its one raw
            schema, and the shared ingest role is removed from that schema. A
            worker on another host then holds a credential that can damage one
            vendor's raw data, not every vendor's.
        owner_role: the role that owns, and creates, the raw schemas' tables.
            See _default_privileges.
        partition_health: also grant EXECUTE on control.partition_health() to
            the read and monitor roles; only when that function is emitted too.
        source_state: also grant EXECUTE on the hold-out functions
            (source_state_sql()) to the ingest role and every remote writer,
            and to nobody else; only when those functions are emitted too.
        shared_keeps_remote: TRANSITIONAL. The shared ingest role keeps write
            access to the remote writers' schemas as well, so the remote role
            can be created and granted before the remote host switches to it --
            revoking first would take that host's source dark until it does.
            The output says so in a comment; drop the flag once the switch is
            done, and the next apply revokes.

    THINGS THAT HAVE ALREADY GONE WRONG HERE:

    Sequence privileges. Both run tables have a `bigserial` primary key, so a
    role that may INSERT into control.ingest_run still cannot do it without
    USAGE on the underlying sequence. The failure arrives on the first write of
    the first run, long after the grant looked complete.

    The transform's control grants. It is easy to reason that the transform only
    reads raw and writes mart, and to forget that it also records its own run
    history, watermark and coverage. Missing those, it dies at the first insert
    with a permission error that names a table nobody was thinking about.

    Blanket control grants. Both workers used to get INSERT, UPDATE on every
    control table, so whoever held the ingest password -- including a host in
    another zone -- could forge transform_coverage (and the raw-expiry gate
    would then drop raw nobody reported), forge SUCCESS rows, re-enable a pack
    an operator had disabled, or move the other job's watermark. Each job now
    writes only its own tables; see _control_grants.

    ALTER DEFAULT PRIVILEGES matters because raw tables are partitioned and new
    monthly partitions are created continuously. Without it, grants cover
    today's partitions and silently fail to cover next month's.
    """
    for name in raw_schemas:
        validate_identifier(name)
    for name in mart_tables:
        validate_identifier(name)
    for role in (ingest_role, transform_role, read_role, monitor_role, owner_role):
        if role is not None:
            validate_identifier(role)
    remote = _parse_remote(remote_ingest, raw_schemas)

    writer = "SELECT, INSERT, UPDATE"
    out: list[str] = []

    if ingest_role:
        out.append(f"-- {ingest_role}: lands raw records and records its runs")
        for schema in raw_schemas:
            if schema in remote and shared_keeps_remote:
                out.append(
                    f"-- TRANSITIONAL: {ingest_role} keeps {schema} until "
                    f"{remote[schema]}'s host has switched to it; this grant is "
                    "revoked once the transition flag is dropped"
                )
            elif schema in remote:
                # A GRANT never revokes, so on a warehouse converged before the
                # remote role existed the shared role would keep this schema.
                out.append(
                    f"-- {schema} belongs to remote writer {remote[schema]}, "
                    f"not {ingest_role}"
                )
                out.append(f"REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {ingest_role};")
                out.extend(
                    _default_privileges(schema, writer, ingest_role, owner_role, revoke=True)
                )
                out.append(f"REVOKE USAGE ON SCHEMA {schema} FROM {ingest_role};")
                continue
            out.append(f"GRANT USAGE ON SCHEMA {schema} TO {ingest_role};")
            out.append(f"GRANT {writer} ON ALL TABLES IN SCHEMA {schema} TO {ingest_role};")
            out.extend(_default_privileges(schema, writer, ingest_role, owner_role))
        out.extend(_control_grants(ingest_role, _INGEST_WRITES))
        if source_state:
            out.extend(_hold_out_grants(ingest_role))
        out.append("")

    for schema, role in remote.items():
        out.append(f"-- {role}: remote writer for {schema} only, and its own runs")
        out.append(f"GRANT USAGE ON SCHEMA {schema} TO {role};")
        out.append(f"GRANT {writer} ON ALL TABLES IN SCHEMA {schema} TO {role};")
        out.extend(_default_privileges(schema, writer, role, owner_role))
        out.extend(_control_grants(role, _INGEST_WRITES))
        if source_state:
            out.extend(_hold_out_grants(role))
        out.append("")

    if transform_role:
        out.append(f"-- {transform_role}: reads raw, writes mart, records its runs")
        for schema in raw_schemas:
            out.append(f"GRANT USAGE ON SCHEMA {schema} TO {transform_role};")
            out.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {transform_role};")
            out.extend(_default_privileges(schema, "SELECT", transform_role, owner_role))
        out.extend(_control_grants(transform_role, _TRANSFORM_WRITES))
        for table in mart_tables:
            # DELETE is required: rollups are rebuilt by clearing the day first.
            out.append(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {transform_role};"
            )
        out.append("")

    if read_role:
        out.append(
            f"-- {read_role}: reporting. Reads the mart layer, and control so "
            "pipeline health can be shown beside it. Never raw."
        )
        for table in mart_tables:
            out.append(f"GRANT SELECT ON {table} TO {read_role};")
        out.append(f"GRANT USAGE ON SCHEMA control TO {read_role};")
        out.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA control TO {read_role};")
        if partition_health:
            out.append(
                f"GRANT EXECUTE ON FUNCTION control.partition_health() TO {read_role};"
            )
        out.append("")

    if monitor_role:
        out.append(
            f"-- {monitor_role}: external monitoring. Run history and partition "
            "health, read-only; no raw and no mart."
        )
        out.append(f"GRANT USAGE ON SCHEMA control TO {monitor_role};")
        out.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA control TO {monitor_role};")
        if partition_health:
            out.append(
                f"GRANT EXECUTE ON FUNCTION control.partition_health() TO {monitor_role};"
            )
        out.append("")

    return "\n".join(out) + ("\n" if out else "")
