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

The same check covers each transform target's RAW, FACT and ROLLUP tables
(`verify_target_schema`). Those are created with CREATE TABLE IF NOT EXISTS,
so a column a newer package adds is a no-op against an existing warehouse, and
the target then fails every run with an UndefinedColumn traceback and a
frozen mart. Two different remedies apply, and the report says which: a
column the target's DDL also adds with `ALTER TABLE ... ADD COLUMN IF NOT
EXISTS` is fixed by re-applying the package's DDL; a column only its CREATE
TABLE declares has no migration at all, which is a bug in the package (or the
pack) that shipped it, not something re-applying can fix.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any

from ..schema import control_sql, raw_table_sql

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..transform.base import Target

__all__ = [
    "ControlSchemaDrift",
    "TargetSchemaDrift",
    "expected_control_columns",
    "expected_target_columns",
    "verify_control_schema",
    "verify_target_schema",
]

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


class TargetSchemaDrift(RuntimeError):
    """A target's raw, fact or rollup table lacks columns this package writes."""


#: CREATE TABLE in a target's DDL: indented, optionally schema-qualified, body
#: closed by a line starting with ")" (which may carry PARTITION BY ...).
_TARGET_CREATE_RE = re.compile(
    r"^\s*CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s*\(\s*\n"
    r"(.*?)^\s*\)",
    re.MULTILINE | re.DOTALL,
)
_TARGET_ALTER_RE = re.compile(
    r"^\s*ALTER TABLE ([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?) ADD COLUMN IF NOT EXISTS "
    r"([a-z_][a-z0-9_]*)",
    re.MULTILINE,
)


def _parse_ddl(ddl: str) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    """({table: columns}, {table: columns that have a migration}) from DDL text."""
    columns: dict[str, list[str]] = {}
    migrated: dict[str, set[str]] = {}
    for match in _TARGET_CREATE_RE.finditer(ddl):
        declared = columns.setdefault(match.group(1), [])
        for column in _columns_from_create_body(match.group(2)):
            if column not in declared:
                declared.append(column)
    for table, column in _TARGET_ALTER_RE.findall(ddl):
        declared = columns.setdefault(table, [])
        if column not in declared:
            declared.append(column)
        migrated.setdefault(table, set()).add(column)
    return columns, migrated


def expected_target_columns(
    targets: Iterable[Target],
) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    """Every table the targets read or write, its columns, and which have a migration.

    Raises RuntimeError -- a package bug, not drift -- when a target declares
    DDL for its fact or rollup table that this parser cannot read, for the same
    reason expected_control_columns() does.
    """
    columns: dict[str, list[str]] = {}
    migrated: dict[str, set[str]] = {}
    for target in targets:
        schema, _, table = target.raw_table.partition(".")
        ddl = [raw_table_sql(schema, table)] if table else []
        ddl += [d for d in (target.fact_ddl, target.rollup_ddl) if d]
        for text in ddl:
            found, moves = _parse_ddl(text)
            for name, cols in found.items():
                declared = columns.setdefault(name, [])
                declared.extend(c for c in cols if c not in declared)
            for name, moved in moves.items():
                migrated.setdefault(name, set()).update(moved)
        for created, ddl_text in ((target.fact_table, target.fact_ddl),
                                  (target.rollup_table, target.rollup_ddl)):
            if ddl_text and created and not columns.get(created):
                raise RuntimeError(
                    f"target {target.name}: could not read the columns of {created} from "
                    "its DDL; its shape has changed in a way schema_check no longer "
                    "understands"
                )
    return columns, migrated


def verify_target_schema(conn: Any, targets: Sequence[Target]) -> None:
    """Raise TargetSchemaDrift if any table the targets touch is behind their DDL.

    Columns are read from pg_attribute through to_regclass(), not from
    information_schema: to_regclass resolves an unqualified mart table exactly
    the way the target's own SQL will (search_path), and pg_attribute is
    readable regardless of privileges, so a role that may only SELECT a table
    still sees all of its columns.

    As with the control check, a warehouse AHEAD of the package is fine.
    """
    expected, migrated = expected_target_columns(targets)
    problems: list[str] = []
    needs_package_fix: list[str] = []
    with conn.cursor() as cur:
        for table, columns in expected.items():
            cur.execute(
                "SELECT a.attname FROM pg_attribute a "
                "WHERE a.attrelid = to_regclass(%s) AND a.attnum > 0 AND NOT a.attisdropped",
                (table,),
            )
            present = {row[0] for row in cur.fetchall()}
            if not present:
                problems.append(f"{table} does not exist")
                continue
            missing = [c for c in columns if c not in present]
            if not missing:
                continue
            problems.append(f"{table} is missing column(s): {', '.join(missing)}")
            unmigrated = [c for c in missing if c not in migrated.get(table, set())]
            if unmigrated:
                needs_package_fix.append(f"{table} ({', '.join(unmigrated)})")
    if not problems:
        return
    message = "warehouse tables are behind this package: " + "; ".join(problems) + ". "
    if needs_package_fix:
        message += (
            "No migration ships for "
            + ", ".join(needs_package_fix)
            + ": the target's DDL needs an ALTER TABLE ... ADD COLUMN IF NOT EXISTS "
            "for each (a package bug), or the column must be added by hand. "
            "Anything else: "
        )
    message += (
        "apply the package's DDL as the schema owner: "
        'python -m secops_ingest.schema | psql "$SECOPS_DB_DSN"'
    )
    raise TargetSchemaDrift(message)
