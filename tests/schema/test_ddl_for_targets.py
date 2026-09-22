"""One function builds a target's DDL, so the emitter and `pack enable` cannot drift."""

from __future__ import annotations

import dataclasses

from secops_ingest.schema import ddl_for_targets
from secops_ingest.transform.base import Target
from secops_ingest.transform.targets import EXAMPLE, TARGETS

# A minimal, self-contained Target -- not one of the real TARGETS -- so these
# tests pin the partition condition itself rather than happening to pass
# because every real target today declares itself partitioned. Satisfies
# Target.__post_init__: upsert_sql references %(since)s with a cast (never a
# bare "%(since)s IS NULL"), fact_ddl names fact_table, and rollup is left out
# entirely (rollup_table/rollup_sql must be set together or not at all).
_UNPARTITIONED = Target(
    name="synthetic",
    raw_table="raw_synthetic.events",
    fact_table="mart_fact_synthetic",
    fact_date_expr="occurred_at",
    upsert_sql="""
        INSERT INTO mart_fact_synthetic (id, occurred_at)
        SELECT source_id, _event_time
        FROM raw_synthetic.events
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        ON CONFLICT (id) DO NOTHING
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_synthetic (
            id          text        PRIMARY KEY,
            occurred_at timestamptz NOT NULL
        );
    """,
)

_PARTITIONED = dataclasses.replace(
    _UNPARTITIONED,
    fact_ddl=_UNPARTITIONED.fact_ddl + "\n-- PARTITION BY RANGE (occurred_at)\n",
)


def test_includes_raw_table_and_its_partitions() -> None:
    sql = ddl_for_targets([EXAMPLE])
    assert "raw_example" in sql
    assert "PARTITION" in sql


def test_includes_the_fact_ddl_the_target_declares() -> None:
    sql = ddl_for_targets([EXAMPLE])
    assert EXAMPLE.fact_table in sql


def test_unpartitioned_fact_ddl_emits_no_mart_partitions() -> None:
    # A DO block against an unpartitioned table fails, and would fail on every
    # deploy -- the emitter already guards this and the shared function must too.
    sql = ddl_for_targets([_UNPARTITIONED])
    assert "raw_synthetic" in sql
    assert _UNPARTITIONED.fact_table in sql
    assert f"monthly partitions for {_UNPARTITIONED.fact_table}" not in sql


def test_partitioned_fact_ddl_does_emit_mart_partitions() -> None:
    sql = ddl_for_targets([_PARTITIONED])
    assert f"monthly partitions for {_PARTITIONED.fact_table}" in sql


def test_is_idempotent_ddl_only() -> None:
    sql = ddl_for_targets(list(TARGETS.values()))
    assert "DROP " not in sql


def test_empty_input_is_empty_output() -> None:
    assert ddl_for_targets([]).strip() == ""
