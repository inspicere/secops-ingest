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
    grants_sql,
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


# -- grants -------------------------------------------------------------------


def g(**kw: object) -> str:
    return grants_sql(["raw_wazuh"], ["mart_fact_wazuh_alerts", "mart_rollup_wazuh_daily"], **kw)  # type: ignore[arg-type]


def test_no_roles_means_no_grants() -> None:
    """Role naming is a local convention; assume nothing."""
    assert g() == ""


def test_sequence_privileges_are_granted() -> None:
    """control.ingest_run has a bigserial key.

    INSERT alone is not enough — the role also needs USAGE on the sequence, and
    the failure lands on the first write of the first run.
    """
    for role in ("ingest_role", "transform_role"):
        sql = g(**{role: "r"})
        assert "USAGE, SELECT ON ALL SEQUENCES IN SCHEMA control" in sql


def test_transform_gets_control_grants() -> None:
    """The transform reads raw and writes mart — and records its own runs.

    Forgetting the third has already broken this project once: it died at the
    first insert, naming a table nobody was thinking about.
    """
    sql = g(transform_role="wh_transform")
    assert "ON ALL TABLES IN SCHEMA control TO wh_transform" in sql


def test_transform_can_delete_from_the_mart() -> None:
    """Rollups are rebuilt by clearing the day first, so DELETE is required."""
    sql = g(transform_role="wh_transform")
    assert "SELECT, INSERT, UPDATE, DELETE ON mart_rollup_wazuh_daily" in sql


def test_default_privileges_cover_future_partitions() -> None:
    """Raw tables gain a new partition every month.

    Without ALTER DEFAULT PRIVILEGES the grants cover today's partitions and
    silently fail to cover next month's.
    """
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA raw_wazuh" in g(ingest_role="wh_ingest")


def test_read_role_sees_the_mart_and_nothing_else() -> None:
    sql = g(read_role="wh_metabase")
    assert "GRANT SELECT ON mart_fact_wazuh_alerts TO wh_metabase;" in sql
    assert "raw_wazuh" not in sql
    assert "control" not in sql
    assert "INSERT" not in sql and "DELETE" not in sql


def test_role_names_are_validated() -> None:
    with pytest.raises(InvalidIdentifier):
        g(ingest_role="r; DROP SCHEMA control CASCADE")


def test_grants_are_emitted_after_the_tables_they_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """GRANT ... ON ALL TABLES IN SCHEMA is evaluated when it runs.

    Emitted before the CREATE statements, it would silently cover nothing.
    """
    assert main(["--target", "wazuh_alerts", "--ingest-role", "wh_ingest"]) == 0
    out = capsys.readouterr().out
    assert out.index("CREATE TABLE IF NOT EXISTS raw_wazuh.alerts") < out.index("GRANT USAGE")


# -- raw tables with no transform target --------------------------------------


def test_raw_only_emits_just_that_table(capsys: pytest.CaptureFixture[str]) -> None:
    """A deployment may land sources whose connector is not in this repo."""
    assert main(["--raw", "raw_phisher.messages", "--no-control"]) == 0
    out = capsys.readouterr().out
    assert "raw_phisher.messages" in out
    # No target was named, so no target DDL should appear.
    assert "mart_fact_wazuh_alerts" not in out
    assert "mart_fact_defectdojo_findings" not in out


def test_raw_and_target_together_emit_both(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--raw", "raw_phisher.messages", "--target", "wazuh_alerts"]) == 0
    out = capsys.readouterr().out
    assert "raw_phisher.messages" in out
    assert "mart_fact_wazuh_alerts" in out


def test_raw_gets_partitions_like_any_other(capsys: pytest.CaptureFixture[str]) -> None:
    """Missing partitions fail at midnight on the first regardless of origin."""
    assert main(["--raw", "raw_phisher.messages", "--no-control"]) == 0
    out = capsys.readouterr().out
    assert "monthly partitions for raw_phisher.messages" in out
    assert "generate_series" in out


def test_raw_schema_included_in_grants(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--raw", "raw_phisher.messages", "--ingest-role", "wh_ingest"]) == 0
    out = capsys.readouterr().out
    assert "GRANT USAGE ON SCHEMA raw_phisher TO wh_ingest;" in out


@pytest.mark.parametrize("bad", ["nodot", ".messages", "raw_phisher."])
def test_malformed_raw_spec_is_rejected(bad: str) -> None:
    with pytest.raises(SystemExit):
        main(["--raw", bad])


def test_hostile_raw_identifier_is_rejected() -> None:
    with pytest.raises(InvalidIdentifier):
        main(["--raw", "raw_x; DROP SCHEMA control CASCADE.messages", "--no-control"])


def test_raw_partitions_are_created_in_the_parents_schema() -> None:
    """An unqualified %I resolves against search_path, not the parent's schema.

    Partitions of raw_phisher.messages were landing in public as
    messages_2026_09 -- attached to the correct parent, in the wrong schema.
    They worked, so a partition COUNT looked right: pg_inherits reports the
    relationship wherever the child lives. What broke silently was everything
    that reasons about schemas, including ALTER DEFAULT PRIVILEGES.
    """
    sql = partitions_sql("raw_phisher", "messages")
    assert "%I.%I PARTITION OF raw_phisher.messages" in sql
    assert "'raw_phisher'," in sql


def test_mart_partitions_stay_unqualified() -> None:
    """Mart tables are created unqualified, so their partitions must match."""
    sql = mart_partition_sql("mart_fact_wazuh_alerts")
    assert "%I PARTITION OF mart_fact_wazuh_alerts" in sql
    assert "%I.%I" not in sql
