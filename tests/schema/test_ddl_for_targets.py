"""One function builds a target's DDL, so the emitter and `pack enable` cannot drift."""

from __future__ import annotations

from secops_ingest.schema import ddl_for_targets
from secops_ingest.transform.targets import EXAMPLE, TARGETS


def test_includes_raw_table_and_its_partitions() -> None:
    sql = ddl_for_targets([EXAMPLE])
    assert "raw_example" in sql
    assert "PARTITION" in sql


def test_includes_the_fact_ddl_the_target_declares() -> None:
    sql = ddl_for_targets([EXAMPLE])
    assert EXAMPLE.fact_table in sql


def test_only_partitions_what_declares_itself_partitioned() -> None:
    # A DO block against an unpartitioned table fails, and would fail on every
    # deploy -- the emitter already guards this and the shared function must too.
    unpartitioned = [t for t in TARGETS.values() if t.fact_ddl and "PARTITION BY RANGE" not in t.fact_ddl]
    for target in unpartitioned:
        sql = ddl_for_targets([target])
        assert f"monthly partitions for {target.fact_table}" not in sql


def test_is_idempotent_ddl_only() -> None:
    sql = ddl_for_targets(list(TARGETS.values()))
    assert "DROP " not in sql


def test_empty_input_is_empty_output() -> None:
    assert ddl_for_targets([]).strip() == ""
