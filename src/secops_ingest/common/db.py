"""PostgreSQL access for ingestion workers.

Requires the `postgres` extra:  pip install secops-ingest[postgres]

Design notes:
  * Table and column names cannot be parameterised, so every identifier is
    wrapped in psycopg.sql.Identifier rather than interpolated. Identifiers
    reach here from configuration, which is not the same as trusted.
  * Upserts target the natural key. Re-running a failed job is therefore safe,
    which is the property that makes recovery boring.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

try:
    import psycopg
    from psycopg import sql
except ImportError as exc:  # pragma: no cover - depends on extra
    raise ImportError(
        "database access requires the 'postgres' extra: "
        "pip install secops-ingest[postgres]"
    ) from exc


def _quote(value: str) -> str:
    """Quote a libpq connection-string value.

    A leased password is generated and can contain spaces, quotes and
    backslashes. libpq's keyword/value format needs those escaped inside
    single quotes, and an unescaped one would silently truncate the value --
    which presents as an authentication failure against a credential that is
    in fact correct.
    """
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def resolve_dsn(provider: object | None = None) -> str:
    """Return a DSN, leasing a credential if one is configured.

    THE LEASED CREDENTIAL IS NEVER WRITTEN ANYWHERE. It is assembled into a
    connection string in memory and handed to psycopg. This is what replaces
    the PGPASSFILE: there is no longer a password to put in a file.

    Environment:
        SECOPS_DB_LEASE     Vault path, e.g. database/creds/ingest
        SECOPS_DB_BASE_DSN  everything but the credential: host, dbname, sslmode
        SECOPS_DB_DSN       a complete static DSN, for dev and for Metabase
    """
    lease_path = os.environ.get("SECOPS_DB_LEASE")
    if not lease_path:
        dsn = os.environ.get("SECOPS_DB_DSN")
        if not dsn:
            raise RuntimeError("SECOPS_DB_DSN is not set")
        return dsn

    base = os.environ.get("SECOPS_DB_BASE_DSN")
    if not base:
        raise RuntimeError(
            "SECOPS_DB_LEASE is set but SECOPS_DB_BASE_DSN is not; it must carry "
            "host, dbname and sslmode, which a lease does not provide"
        )
    leaser = getattr(provider, "lease", None)
    if not callable(leaser):
        raise RuntimeError(
            "SECOPS_DB_LEASE is set but no provider can issue leases; the mapped "
            "provider's root must be vault_agent"
        )
    data = leaser(lease_path)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise RuntimeError(f"lease {lease_path} returned no username and password pair")

    from ..redaction import register_secret

    register_secret(password)
    return f"{base} user={_quote(username)} password={_quote(password)}"


@contextmanager
def connect(provider: object | None = None) -> Iterator[psycopg.Connection]:
    """Yield a connection with autocommit off, committing on clean exit."""
    with psycopg.connect(resolve_dsn(provider)) as conn:
        yield conn


def _split_ident(qualified: str) -> sql.Identifier:
    """Turn 'schema.table' into a properly quoted Identifier."""
    parts = qualified.split(".")
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"expected 'schema.table', got {qualified!r}")
    return sql.Identifier(*parts)


# --- run bookkeeping -------------------------------------------------------

def start_run(conn: psycopg.Connection, source: str, *, posture: str | None = None) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.ingest_run (source, status, posture) "
            "VALUES (%s, 'RUNNING', %s) RETURNING run_id",
            (source, posture),
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError(
                "INSERT ... RETURNING run_id produced no row for control.ingest_run"
            )
        run_id = row[0]
    conn.commit()          # visible immediately, so a crash leaves a RUNNING row
    return int(run_id)


def finish_run(
    conn: psycopg.Connection,
    run_id: int,
    status: str,
    rows_read: int = 0,
    rows_written: int = 0,
    error: str | None = None,
) -> None:
    if status not in ("SUCCESS", "FAILED"):
        raise ValueError(f"invalid terminal status: {status}")
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE control.ingest_run SET ended_at = now(), status = %s, "
            "rows_read = %s, rows_written = %s, error_summary = %s "
            "WHERE run_id = %s",
            (status, rows_read, rows_written, (error or "")[:2000] or None, run_id),
        )
    conn.commit()


# --- watermarks ------------------------------------------------------------

def get_watermark(conn: psycopg.Connection, source: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cursor_value FROM control.ingest_watermark WHERE source = %s",
            (source,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def set_watermark(conn: psycopg.Connection, source: str, value: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.ingest_watermark (source, cursor_value, updated_at) "
            "VALUES (%s, %s, now()) "
            "ON CONFLICT (source) DO UPDATE SET cursor_value = EXCLUDED.cursor_value, "
            "updated_at = now()",
            (source, str(value)),
        )
    conn.commit()


# --- landing ---------------------------------------------------------------

def upsert_many(
    conn: psycopg.Connection,
    table: str,
    rows: Sequence[tuple[str, Any, Any, int | None]],
    columns: Iterable[str] = ("source_id", "payload", "_event_time", "_source_run_id"),
    key: Sequence[str] = ("source_id", "_event_time"),
) -> int:
    """Idempotently upsert rows, returning the number submitted.

    `key` must match the table's primary key. Partitioned raw tables require the
    partition column in the key, hence ('source_id', '_event_time') rather than
    ('source_id',) alone - see docs/architecture/retention-and-storage.md.
    """
    rows = list(rows)
    if not rows:
        return 0

    cols = list(columns)
    updatable = [c for c in cols if c not in key]

    stmt = sql.SQL(
        "INSERT INTO {table} ({cols}) VALUES ({ph}) "
        "ON CONFLICT ({key}) DO UPDATE SET {sets}"
    ).format(
        table=_split_ident(table),
        cols=sql.SQL(", ").join(map(sql.Identifier, cols)),
        ph=sql.SQL(", ").join(sql.Placeholder() * len(cols)),
        key=sql.SQL(", ").join(map(sql.Identifier, key)),
        sets=sql.SQL(", ").join(
            sql.SQL("{c} = EXCLUDED.{c}").format(c=sql.Identifier(c)) for c in updatable
        ),
    )

    with conn.cursor() as cur:
        cur.executemany(stmt, rows)
    conn.commit()
    return len(rows)
