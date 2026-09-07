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


@dataclass(frozen=True)
class Target:
    """One raw -> reporting derivation."""

    #: Identifier used in control.transform_run / _watermark / _coverage.
    name: str

    #: Source table, e.g. "raw_phisher.messages".
    raw_table: str

    #: Destination, e.g. "mart_fact_phisher_messages".
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
