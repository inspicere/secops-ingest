"""Pack state in the warehouse: which packs are installed and may run.

Requires the `postgres` extra:  pip install secops-ingest[postgres]

Design notes:
  * Table and column names cannot be parameterised, so every identifier is
    wrapped in psycopg.sql.Identifier rather than interpolated -- see
    ``secops_ingest.common.db`` for the same convention.
  * A missing `control.pack` table reads as "no state", never an error.
    Warehouses provisioned before this change have no such table, and a
    worker that raised would turn an upgrade into a silent outage the first
    time a timer fired. PostgreSQL aborts every later statement on a
    connection whose transaction has failed, so the caught error is followed
    by an explicit rollback before the connection is used again.
  * `set_state` upserts on `name` and preserves history: moving to ENABLED
    stamps `enabled_at` and leaves `disabled_at`; moving to DISABLED is the
    mirror image. Nothing here ever clears either timestamp.

Nothing outside this module may import it at module scope: `packs/registry.py`,
`packs/model.py` and the `list` path in `packs/__main__.py` must keep working
with no `psycopg` installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

try:
    import psycopg
    from psycopg import sql
except ImportError as exc:  # pragma: no cover - depends on extra
    raise ImportError(
        "database access requires the 'postgres' extra: "
        "pip install secops-ingest[postgres]"
    ) from exc

_STATES = ("ENABLED", "DISABLED")


def validate_state(value: str) -> str:
    """Return `value` unchanged if it is a recognised pack state.

    Raises:
        ValueError: naming both accepted values, so a caller sees what is
            actually allowed rather than just what it typed.
    """
    if value not in _STATES:
        raise ValueError(f"state must be one of {_STATES}, got {value!r}")
    return value


@dataclass(frozen=True)
class PackState:
    """One row of `control.pack`."""

    name: str
    version: str
    state: str
    enabled_at: datetime | None
    disabled_at: datetime | None


def _row_to_state(row: tuple[str, str, str, datetime | None, datetime | None]) -> PackState:
    name, version, state, enabled_at, disabled_at = row
    return PackState(
        name=name,
        version=version,
        state=state,
        enabled_at=enabled_at,
        disabled_at=disabled_at,
    )


def get_state(conn: psycopg.Connection, name: str) -> PackState | None:
    """Return the pack's stored state, or None if it has none.

    Also returns None -- rather than raising -- when `control.pack` does not
    exist at all, which is the shape of a warehouse from before this change.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, version, state, enabled_at, disabled_at "
                "FROM control.pack WHERE name = %s",
                (name,),
            )
            row = cur.fetchone()
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return None
    return _row_to_state(row) if row is not None else None


def all_states(conn: psycopg.Connection) -> dict[str, PackState]:
    """Return every stored pack state, keyed by name.

    Returns {} -- rather than raising -- when `control.pack` does not exist.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, version, state, enabled_at, disabled_at FROM control.pack"
            )
            rows = cur.fetchall()
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return {}
    return {row[0]: _row_to_state(row) for row in rows}


def set_state(conn: psycopg.Connection, name: str, version: str, state: str) -> None:
    """Upsert a pack's state, preserving enabled_at/disabled_at history.

    Moving to ENABLED sets enabled_at = now() and leaves disabled_at as it
    was; moving to DISABLED is the mirror image. Re-applying the same state
    is idempotent -- it re-stamps the corresponding timestamp, not an error.
    """
    validate_state(state)
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                "INSERT INTO control.pack (name, version, state, enabled_at, disabled_at) "
                "VALUES (%s, %s, %s, {new_enabled_at}, {new_disabled_at}) "
                "ON CONFLICT (name) DO UPDATE SET "
                "version = EXCLUDED.version, state = EXCLUDED.state, "
                "enabled_at = {upsert_enabled_at}, disabled_at = {upsert_disabled_at}"
            ).format(
                # A fresh row has no prior timestamp to preserve, so the state
                # being set now is the only one that can be stamped.
                new_enabled_at=sql.SQL("now()" if state == "ENABLED" else "NULL"),
                new_disabled_at=sql.SQL("now()" if state == "DISABLED" else "NULL"),
                # An existing row keeps the other column's history untouched.
                upsert_enabled_at=sql.SQL(
                    "now()" if state == "ENABLED" else "control.pack.enabled_at"
                ),
                upsert_disabled_at=sql.SQL(
                    "now()" if state == "DISABLED" else "control.pack.disabled_at"
                ),
            ),
            (name, version, state),
        )
    conn.commit()


def delete_state(conn: psycopg.Connection, name: str) -> None:
    """Remove a pack's row entirely, e.g. when it is fully decommissioned."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM control.pack WHERE name = %s", (name,))
    conn.commit()


def apply_ddl(conn: psycopg.Connection, sql_text: str) -> None:
    """Execute schema DDL (e.g. `schema.control_sql()`) and commit it."""
    with conn.cursor() as cur:
        cur.execute(sql_text)
    conn.commit()
