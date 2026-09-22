"""Transform target definition.

A target is declarative: it names its tables and supplies the SQL that derives
reporting rows from raw. The runner owns everything that must not vary —
watermarking, rollup recomputation, the coverage ledger, and run bookkeeping.

Retention applies to the reporting layer, not to raw (ADR-0002), so raw is a
bounded re-derivation buffer. That makes this stage load-bearing: if it stops
for longer than the raw window, the period is lost permanently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Target:
    """One raw -> reporting derivation."""

    #: Identifier used in control.transform_run / _watermark / _coverage.
    name: str

    #: Source table, e.g. "raw_wazuh.alerts".
    raw_table: str

    #: Destination, e.g. "mart_fact_wazuh_alerts".
    fact_table: str

    #: Upsert deriving facts from raw. Receives %(since)s — the previous
    #: watermark, or NULL on first run — and MUST be idempotent.
    upsert_sql: str

    #: Expression on the FACT table yielding the reporting date. Used to decide
    #: which days need rollup recomputation and which months are covered.
    fact_date_expr: str

    #: Optional pre-aggregation for high-volume sources.
    rollup_table: str | None = None
    rollup_sql: str | None = None

    #: DDL creating fact_table / rollup_table.
    #:
    #: Carried by the target rather than kept in a deployment repo, because a
    #: target that declares SQL writing into a table nobody creates is only half
    #: a definition -- and the half that is missing fails at 3am on first run,
    #: not at review time.
    fact_ddl: str | None = None
    rollup_ddl: str | None = None

    #: Re-derive every row on every run, ignoring the incremental watermark.
    #:
    #: OFF for every source-shaped target, and it must stay that way: the whole
    #: point of the watermark is that a run costs the changed slice rather than
    #: the collection.
    #:
    #: ON for a target that JOINS a second table the watermark cannot see. The
    #: runner's staleness guard asks one question -- has `raw_table` received
    #: anything since the watermark -- and skips the upsert entirely when the
    #: answer is no. For a join, that answer is not the same as "is there work to
    #: do": the other side can change with `raw_table` completely untouched, and
    #: those rows then never get re-derived. A predicate inside the upsert cannot
    #: save it, because the upsert is what gets skipped.
    #:
    #: Only worth setting on a target whose full derive is cheap. Measured for
    #: incident_lifecycle: ~48k rows, well under a second.
    full_refresh: bool = False

    def __post_init__(self) -> None:
        if "%(since)s" not in self.upsert_sql:
            raise ValueError(
                f"target {self.name}: upsert_sql must reference %(since)s, or every "
                "run would reprocess the entire raw table"
            )
        if "%(since)s IS NULL" in self.upsert_sql.replace("  ", " "):
            raise ValueError(
                f"target {self.name}: cast the watermark parameter "
                "(%(since)s::timestamptz) — PostgreSQL cannot infer a type for a "
                "bare parameter inside IS NULL and raises AmbiguousParameter"
            )
        if bool(self.rollup_table) != bool(self.rollup_sql):
            raise ValueError(
                f"target {self.name}: rollup_table and rollup_sql must be set together"
            )
        # A DDL block that creates something other than the table this target
        # writes to is worse than none: it succeeds, and the upsert then fails
        # against a table that does not exist.
        if self.fact_ddl and self.fact_table not in self.fact_ddl:
            raise ValueError(
                f"target {self.name}: fact_ddl does not create {self.fact_table}"
            )
        if self.rollup_ddl and self.rollup_table and self.rollup_table not in self.rollup_ddl:
            raise ValueError(
                f"target {self.name}: rollup_ddl does not create {self.rollup_table}"
            )
        if self.rollup_ddl and not self.rollup_table:
            raise ValueError(
                f"target {self.name}: rollup_ddl given but no rollup_table"
            )


def should_skip(target: Target, since: Any, new_mark: Any) -> bool:
    """Is there provably nothing to do?

    Pure and separate from execute() deliberately. This guard silently defeated
    a correctness fix that lived inside a target's upsert_sql: the fix was a
    predicate in the WHERE clause, and this decides whether that statement runs
    at all. Nothing executed it, so three reviews of the SQL all passed. Keeping
    it here means the decision is testable without a database, for the same
    reason common/watermark.py exists.

    A full-refresh target is never skipped: its work is not measured by whether
    `raw_table` moved.
    """
    if target.full_refresh:
        return False
    return new_mark is None or (since is not None and new_mark <= since)


def effective_since(target: Target, since: Any) -> Any:
    """The value bound to %(since)s. None on a full refresh, so the upsert's
    `%(since)s::timestamptz IS NULL` branch re-derives every row."""
    return None if target.full_refresh else since
