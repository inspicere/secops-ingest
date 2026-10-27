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
        remote_ingest: (role, schema) pairs. Each role writes only its one raw
            schema, and the shared ingest role is removed from that schema. A
            worker on another host then holds a credential that can damage one
            vendor's raw data, not every vendor's.
        owner_role: the role that owns, and creates, the raw schemas' tables.
            See _default_privileges.
        partition_health: also grant EXECUTE on control.partition_health() to
            the read and monitor roles; only when that function is emitted too.
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
        out.append("")

    for schema, role in remote.items():
        out.append(f"-- {role}: remote writer for {schema} only, and its own runs")
        out.append(f"GRANT USAGE ON SCHEMA {schema} TO {role};")
        out.append(f"GRANT {writer} ON ALL TABLES IN SCHEMA {schema} TO {role};")
        out.extend(_default_privileges(schema, writer, role, owner_role))
        out.extend(_control_grants(role, _INGEST_WRITES))
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
