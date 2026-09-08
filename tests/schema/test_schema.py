"""Tests for the warehouse DDL.

The SQL itself is verified by applying it to PostgreSQL 16 (see the commit that
introduced this module). These pin the properties that a green apply would not
catch — a schema that creates cleanly can still be silently wrong.
"""

from __future__ import annotations

import pytest

from secops_ingest.schema import (
    InvalidIdentifier,
    control_sql,
    mart_partition_sql,
    partitions_sql,
    raw_table_sql,
    validate_identifier,
)
from secops_ingest.schema.__main__ import main
from secops_ingest.transform.base import Target
from secops_ingest.transform.targets import TARGETS

# -- identifiers --------------------------------------------------------------


@pytest.mark.parametrize("good", ["raw_wazuh", "alerts", "a", "mart_fact_x_1"])
def test_valid_identifiers_accepted(good: str) -> None:
    assert validate_identifier(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        'x"; DROP TABLE control.ingest_run; --',
        "raw wazuh",
        "Raw_Wazuh",       # partition DDL interpolates unquoted; case would break it
        "1_leading_digit",
        "",
        "x" * 64,
    ],
)
def test_injection_and_malformed_identifiers_rejected(bad: str) -> None:
    """Names reach a DO block where bind parameters are unavailable.

    Interpolation there is only safe because the character set is restricted, so
    this is the check the safety argument rests on.
    """
    with pytest.raises(InvalidIdentifier):
        validate_identifier(bad)


def test_raw_table_sql_rejects_a_hostile_schema_name() -> None:
    with pytest.raises(InvalidIdentifier):
        raw_table_sql("raw_x; DROP SCHEMA control CASCADE", "alerts")


# -- raw tables ---------------------------------------------------------------


def test_partition_key_is_in_the_primary_key() -> None:
    """PostgreSQL requires it, and it is why connectors upsert on that pair."""
    sql = raw_table_sql("raw_wazuh", "alerts")
    assert "PRIMARY KEY (source_id, _event_time)" in sql
    assert "PARTITION BY RANGE (_event_time)" in sql


def test_ingested_at_is_indexed_not_event_time_only() -> None:
    """The transform asks "what landed since my watermark", not "what happened".

    For a mutating source those differ by months, so an _event_time index alone
    would not serve the query the transform actually runs.
    """
    assert "(_ingested_at)" in raw_table_sql("raw_defectdojo", "findings")


def test_payload_gin_index_is_opt_in() -> None:
    """Write-amplifying, and only useful if raw is queried ad hoc."""
    assert "gin (payload)" not in raw_table_sql("raw_wazuh", "alerts")
    assert "gin (payload)" in raw_table_sql("raw_wazuh", "alerts", gin_index=True)


def test_raw_ddl_is_idempotent() -> None:
    sql = raw_table_sql("raw_wazuh", "alerts")
    assert sql.count("IF NOT EXISTS") >= 3


# -- partitions ---------------------------------------------------------------


def test_month_arithmetic_stays_in_postgresql() -> None:
    """Adding an "average month" of seconds in application code drifts.

    It eventually skips or duplicates a month, which surfaces as inserts failing
    at midnight on the first. generate_series over interval '1 month' cannot.
    """
    sql = partitions_sql("raw_wazuh", "alerts")
    assert "generate_series" in sql
    assert "interval '1 month'" in sql


def test_partition_lookahead_must_cover_at_least_next_month() -> None:
    """ahead=0 creates the current month as the last partition.

    Inserts then fail at midnight on the first, with no warning, which is the
    specific failure this window exists to prevent.
    """
    with pytest.raises(ValueError, match="ahead must be"):
        partitions_sql("raw_wazuh", "alerts", ahead=0)
    with pytest.raises(ValueError, match="ahead must be"):
        mart_partition_sql("mart_fact_wazuh_alerts", ahead=0)


def test_partition_creation_is_idempotent() -> None:
    assert "CREATE TABLE IF NOT EXISTS" in partitions_sql("raw_wazuh", "alerts")


# -- control ------------------------------------------------------------------


def test_control_has_the_coverage_ledger() -> None:
    """Raw expiry is gated on it; without the table nothing may drop a partition."""
    sql = control_sql()
    assert "control.transform_coverage" in sql
    assert "PRIMARY KEY (target, period)" in sql


def test_control_is_idempotent() -> None:
    assert "CREATE TABLE IF NOT EXISTS" in control_sql()
    assert "CREATE TABLE control." not in control_sql()


# -- targets carry their own DDL ----------------------------------------------


@pytest.mark.parametrize("target", list(TARGETS.values()), ids=lambda t: t.name)
def test_every_target_can_create_what_it_writes_to(target: Target) -> None:
    """A target whose tables nobody creates fails on first run, not at review."""
    assert target.fact_ddl, f"{target.name} has no fact_ddl"
    assert target.fact_table in target.fact_ddl
    if target.rollup_table:
        assert target.rollup_ddl, f"{target.name} has no rollup_ddl"
        assert target.rollup_table in target.rollup_ddl


# -- the emitter --------------------------------------------------------------


def test_emits_every_target_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    for target in TARGETS.values():
        assert target.fact_table in out
        assert target.raw_table.split(".")[1] in out


def test_target_filter_narrows_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--target", "wazuh_alerts"]) == 0
    out = capsys.readouterr().out
    assert "mart_fact_wazuh_alerts" in out
    assert "mart_fact_defectdojo_findings" not in out


def test_unknown_target_is_an_error_not_silence() -> None:
    with pytest.raises(SystemExit):
        main(["--target", "no_such_target"])


def test_control_can_be_skipped(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-control"]) == 0
    assert "control.ingest_run" not in capsys.readouterr().out


def test_mart_partitions_emitted_only_for_partitioned_facts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A DO block against an unpartitioned table fails on every deploy."""
    assert main(["--target", "defectdojo_findings"]) == 0
    out = capsys.readouterr().out
    target = TARGETS["defectdojo_findings"]
    assert "PARTITION BY RANGE" in (target.fact_ddl or "")
    assert f"monthly partitions for {target.fact_table}" in out
