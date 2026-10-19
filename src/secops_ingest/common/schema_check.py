"""Startup check: is the warehouse's control schema what this package expects?

An upgraded package against an un-migrated warehouse used to die inside its
own run-ledger INSERT with a raw driver traceback -- fifteen frames whose
only real content was "the deployed schema is older than the package". That
is a configuration state, not a crash, so it is reported as one line naming
the table, the missing column(s), and the remedy, and the process exits
non-zero.

The expectation is DERIVED from control_sql() rather than hand-maintained:
that string is the package's own definition of the control schema, and a list
kept separately could silently disagree with it the way the warehouse did.
The parser below only understands the shape of DDL that control_sql()
emits -- one table per CREATE, plain lowercase identifiers, table-level
constraints starting with a keyword -- and tests/schema pins both sides of
that contract.
"""

from __future__ import annotations

import re
from typing import Any

from ..schema import control_sql

__all__ = ["ControlSchemaDrift", "expected_control_columns", "verify_control_schema"]

#: Statement heads that introduce a table-level constraint (or a clause of
#: one) inside a CREATE TABLE body, as opposed to a column declaration. The
#: CHECK continuation lines in control_sql() start with one of these too.
_CONSTRAINT_STARTS = ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT",
                      "EXCLUDE", "LIKE")

_CREATE_TABLE_RE = re.compile(
    r"^CREATE TABLE IF NOT EXISTS control\.([a-z_][a-z0-9_]*)\s*\(\s*\n(.*?)^\);",
    re.MULTILINE | re.DOTALL,
)

_ALTER_ADD_RE = re.compile(
    r"^ALTER TABLE control\.([a-z_][a-z0-9_]*) ADD COLUMN IF NOT EXISTS "
    r"([a-z_][a-z0-9_]*)",
    re.MULTILINE,
)

#: What an operator runs to bring the control schema up to date; quoted in
#: every drift report so the message is actionable on its own.
REMEDY = (
    "Apply the package's own control DDL as the schema owner: "
    'python -m secops_ingest.schema | psql "$SECOPS_DB_DSN"'
)


class ControlSchemaDrift(RuntimeError):
    """The warehouse's control schema lacks what this package needs."""


def _columns_from_create_body(body: str) -> list[str]:
    """Column names declared in a CREATE TABLE body.

    Skips blank lines, ``--`` comments, and table-level constraints. Anything
    else is a column declaration, and its first word is the column name.
    """
    columns: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        first = stripped.split(None, 1)[0]
        if first.upper() in _CONSTRAINT_STARTS:
            continue
        columns.append(first)
    return columns


def expected_control_columns() -> dict[str, list[str]]:
    """Every control table this package expects, and the columns it writes.

    Derived from control_sql(): the CREATE TABLE bodies give the columns a
    fresh warehouse ends up with, the ALTER TABLE ... ADD COLUMN IF NOT EXISTS
    statements give the columns an upgraded warehouse must have gained.
    """
    expected: dict[str, list[str]] = {}
    for match in _CREATE_TABLE_RE.finditer(control_sql()):
        table = match.group(1)
        declared = expected.setdefault(table, [])
        for column in _columns_from_create_body(match.group(2)):
            if column not in declared:
                declared.append(column)
    for table, column in _ALTER_ADD_RE.findall(control_sql()):
        declared = expected.setdefault(table, [])
        if column not in declared:
            declared.append(column)
    if not expected:
        # The package's own DDL no longer parses: that is a bug in this
        # package, and it must fail loudly as one -- not misreport every
        # warehouse as drifted.
        raise RuntimeError(
            "could not derive the control schema expectation from control_sql(); "
            "its shape has changed in a way schema_check no longer understands"
        )
    return expected


def verify_control_schema(conn: Any) -> None:
    """Raise ControlSchemaDrift if `conn`'s control schema is behind the package.

    Runs once per worker invocation, before any run-ledger write: a refused
    run must leave no RUNNING row behind, or the refusal itself becomes the
    next operator mystery.

    The warehouse being AHEAD is fine and expected -- hand-added columns,
    other tools' tables in the same schema. Only what the package needs is
    checked.
    """
    expected = expected_control_columns()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'control'"
        )
        actual: dict[str, set[str]] = {}
        for table_name, column_name in cur.fetchall():
            actual.setdefault(table_name, set()).add(column_name)

    problems: list[str] = []
    for table, columns in expected.items():
        present = actual.get(table)
        if present is None:
            problems.append(f"control.{table} does not exist")
            continue
        missing = [c for c in columns if c not in present]
        if missing:
            problems.append(
                f"control.{table} is missing column(s): {', '.join(missing)}"
            )
    if problems:
        raise ControlSchemaDrift(
            "control schema is behind this package: "
            + "; ".join(problems)
            + ". "
            + REMEDY
        )
