"""Per-table control grants, the monitor and remote roles, DEFAULT partitions,
and the timer-shaped emitter modes.

Text-level: what is emitted, and what is not. tests/schema/
test_grants_integration.py runs the same SQL against a real PostgreSQL to
prove it means what these assertions assume.
"""

from __future__ import annotations

import json
import re

import pytest

from secops_ingest.schema import (
    InvalidIdentifier,
    control_sql,
    control_tables,
    grants_sql,
    mart_partition_sql,
    partition_check_sql,
    partition_health_sql,
    partitions_sql,
)
from secops_ingest.schema.__main__ import main
from secops_ingest.transform.targets import TARGETS


def g(**kw: object) -> str:
    return grants_sql(  # type: ignore[arg-type]
        ["raw_wazuh", "raw_xdr"], ["mart_fact_wazuh_alerts"], **kw
    )


# -- control: read all, write own ---------------------------------------------


def test_control_tables_are_derived_from_the_control_ddl() -> None:
    created = re.findall(r"CREATE TABLE IF NOT EXISTS control\.(\w+)", control_sql())
    assert control_tables() == created
    assert "pack" in control_tables()


@pytest.mark.parametrize(
    ("role", "writes"),
    [
        ("ingest_role", {"ingest_run", "ingest_watermark"}),
        ("transform_role", {"transform_run", "transform_watermark", "transform_coverage"}),
    ],
)
def test_each_worker_writes_only_its_own_control_tables(role: str, writes: set[str]) -> None:
    """A holder of the ingest password must not be able to forge coverage.

    Forged transform_coverage is what lets the raw-expiry gate drop raw that
    was never reported; a writable control.pack re-arms a disabled pack.
    """
    sql = g(**{role: "r"})
    for table in control_tables():
        grant = f"GRANT SELECT, INSERT, UPDATE ON control.{table} TO r;"
        revoke = f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.{table} FROM r;"
        if table in writes:
            assert grant in sql
            assert revoke not in sql
        else:
            # Every control table gets an explicit decision, so a table added
            # to control_sql() later is revoked by default rather than left to
            # whatever an older converge granted.
            assert revoke in sql, table
            assert grant not in sql
    assert "INSERT, UPDATE ON ALL TABLES IN SCHEMA control" not in sql


def test_no_role_may_write_the_pack_table() -> None:
    sql = g(ingest_role="i", transform_role="t", read_role="m", monitor_role="lm")
    assert not re.search(r"GRANT [A-Z, ]*(INSERT|UPDATE)[A-Z, ]* ON control\.pack", sql)


def test_workers_can_read_every_control_table() -> None:
    """The startup drift check reads information_schema.columns, which hides
    tables the role has no privilege on -- so read access is required, or the
    check reports the other job's tables as missing and refuses to run."""
    for role in ("ingest_role", "transform_role"):
        assert "GRANT SELECT ON ALL TABLES IN SCHEMA control TO r;" in g(**{role: "r"})


def test_own_tables_are_never_revoked_and_regranted() -> None:
    """Revoking INSERT from a table the role writes, then granting it back,
    opens a window mid-converge in which a running job's INSERT fails."""
    sql = g(ingest_role="r")
    assert "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.ingest_run FROM r;" not in sql
    assert "REVOKE DELETE, TRUNCATE ON control.ingest_run FROM r;" in sql


def test_sequence_grants_name_tables_that_really_have_a_bigserial() -> None:
    sql = g(ingest_role="i", transform_role="t")
    for table in re.findall(r"ON SEQUENCE control\.(\w+)_run_id_seq", sql):
        assert re.search(
            rf"CREATE TABLE IF NOT EXISTS control\.{table} \(\s*run_id\s+bigserial",
            control_sql(),
        ), table


# -- monitor and read roles ----------------------------------------------------


def test_monitor_role_reads_control_and_nothing_else() -> None:
    sql = g(monitor_role="lm_monitor", partition_health=True)
    assert "GRANT USAGE ON SCHEMA control TO lm_monitor;" in sql
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA control TO lm_monitor;" in sql
    assert "GRANT EXECUTE ON FUNCTION control.partition_health() TO lm_monitor;" in sql
    assert "mart_fact" not in sql
    assert "raw_" not in sql
    assert "INSERT" not in sql


def test_partition_health_is_granted_only_when_it_is_emitted() -> None:
    assert "partition_health" not in g(read_role="m", monitor_role="lm")
    assert "control.partition_health() TO m;" in g(read_role="m", partition_health=True)


def test_monitor_role_name_is_validated() -> None:
    with pytest.raises(InvalidIdentifier):
        g(monitor_role="lm; DROP SCHEMA control CASCADE")


# -- remote writer -------------------------------------------------------------


def test_remote_writer_is_confined_to_its_schema() -> None:
    sql = g(remote_ingest=[("wh_ingest_wazuh", "raw_wazuh")])
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest_wazuh;" in sql
    assert "raw_xdr TO wh_ingest_wazuh" not in sql
    assert "GRANT SELECT, INSERT, UPDATE ON control.ingest_run TO wh_ingest_wazuh;" in sql
    assert (
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.transform_coverage "
        "FROM wh_ingest_wazuh;"
    ) in sql


def test_shared_ingest_role_loses_a_schema_given_to_a_remote_writer() -> None:
    """GRANT never revokes, so the shared role keeps the schema on an existing
    warehouse unless the REVOKE is emitted too."""
    sql = g(ingest_role="wh_ingest", remote_ingest=[("wh_ingest_wazuh", "raw_wazuh")])
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest;" not in sql
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA raw_wazuh FROM wh_ingest;" in sql
    assert "REVOKE USAGE ON SCHEMA raw_wazuh FROM wh_ingest;" in sql
    assert "GRANT USAGE ON SCHEMA raw_xdr TO wh_ingest;" in sql


def test_transition_flag_keeps_the_shared_role_on_the_remote_schema() -> None:
    """The remote role can exist before its host switches; revoking first
    would take that host's source dark in the meantime."""
    sql = g(ingest_role="wh_ingest", remote_ingest=[("wh_ingest_wazuh", "raw_wazuh")],
            shared_keeps_remote=True)
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest;" in sql
    assert "REVOKE USAGE ON SCHEMA raw_wazuh FROM wh_ingest;" not in sql
    assert "TRANSITIONAL" in sql
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest_wazuh;" in sql


def test_transition_flag_is_logged_and_needs_both_roles(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    import logging

    with pytest.raises(SystemExit):
        main(["--target", "wazuh_alerts", "--shared-ingest-keeps-remote"])
    capsys.readouterr()
    with caplog.at_level(logging.WARNING):
        assert main(["--target", "wazuh_alerts", "--ingest-role", "wh_ingest",
                     "--remote-ingest-role", "wh_ingest_wazuh:raw_wazuh",
                     "--shared-ingest-keeps-remote"]) == 0
    assert "not yet confined" in caplog.text
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest;" in capsys.readouterr().out


def test_transform_still_reads_a_remote_writers_schema() -> None:
    sql = g(transform_role="t", remote_ingest=[("w", "raw_wazuh")])
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA raw_wazuh TO t;" in sql


def test_remote_writer_for_an_unknown_schema_is_refused() -> None:
    with pytest.raises(ValueError, match="raw_typo"):
        g(remote_ingest=[("w", "raw_typo")])


def test_one_schema_cannot_have_two_remote_writers() -> None:
    with pytest.raises(ValueError, match="two remote ingest roles"):
        g(remote_ingest=[("a", "raw_wazuh"), ("b", "raw_wazuh")])


def test_remote_writer_names_are_validated() -> None:
    with pytest.raises(InvalidIdentifier):
        g(remote_ingest=[("w; DROP ROLE x", "raw_wazuh")])


# -- default privileges for the owner -----------------------------------------


def test_default_privileges_name_the_owner_when_given() -> None:
    """Default privileges belong to the creating role; without FOR ROLE, a
    table created by the owner rather than by whoever ran this file carries no
    grants at all."""
    sql = g(ingest_role="i", owner_role="wh_owner")
    assert (
        "ALTER DEFAULT PRIVILEGES FOR ROLE wh_owner IN SCHEMA raw_wazuh "
        "GRANT SELECT, INSERT, UPDATE ON TABLES TO i;"
    ) in sql
    # The plain form stays: the role applying the file creates partitions too.
    assert (
        "ALTER DEFAULT PRIVILEGES IN SCHEMA raw_wazuh GRANT SELECT, INSERT, UPDATE "
        "ON TABLES TO i;"
    ) in sql


def test_no_owner_means_no_for_role() -> None:
    assert "FOR ROLE" not in g(ingest_role="i", transform_role="t")


# -- DEFAULT partitions --------------------------------------------------------


def test_raw_parent_gets_a_default_partition_in_its_own_schema() -> None:
    sql = partitions_sql("raw_xsoar", "incidents")
    assert "PARTITION OF raw_xsoar.incidents DEFAULT" in sql
    assert "'raw_xsoar', 'incidents_default'" in sql


def test_mart_parent_gets_an_unqualified_default_partition() -> None:
    sql = mart_partition_sql("mart_fact_xsoar_incidents")
    assert "'CREATE TABLE IF NOT EXISTS %I PARTITION OF mart_fact_xsoar_incidents DEFAULT'" in sql


def test_one_month_blocked_by_default_rows_does_not_stop_the_others() -> None:
    """The handler sits inside the loop, so it skips a month, not the window."""
    sql = partitions_sql("raw_xsoar", "incidents")
    loop = sql[sql.index("LOOP"): sql.index("END LOOP")]
    assert "EXCEPTION WHEN check_violation THEN" in loop
    assert "RAISE WARNING" in loop
    # Only that one error is tolerated; anything else must still fail loudly.
    assert "WHEN OTHERS" not in sql


def test_a_parent_name_too_long_for_its_partitions_is_refused() -> None:
    """PostgreSQL truncates long names with only a NOTICE; the truncated
    partition names would then collide and IF NOT EXISTS would skip months."""
    long_name = "t" * 56
    validate_ok = "t" * 55
    with pytest.raises(InvalidIdentifier):
        partitions_sql("raw_x", long_name)
    partitions_sql("raw_x", validate_ok)
    with pytest.raises(InvalidIdentifier):
        mart_partition_sql(long_name)


def test_every_target_gets_default_partitions_for_raw_and_partitioned_marts() -> None:
    from secops_ingest.schema import ddl_for_targets

    for target in TARGETS.values():
        sql = ddl_for_targets([target])
        assert f"PARTITION OF {target.raw_table} DEFAULT" in sql
        if target.fact_ddl and "PARTITION BY RANGE" in target.fact_ddl:
            assert f"PARTITION OF {target.fact_table} DEFAULT" in sql


# -- partition health and the timer check -------------------------------------


def test_partition_health_is_a_definer_function_with_a_pinned_path() -> None:
    sql = partition_health_sql()
    assert "CREATE OR REPLACE FUNCTION control.partition_health()" in sql
    assert "SECURITY DEFINER" in sql
    assert "SET search_path = pg_catalog, pg_temp" in sql
    assert "REVOKE ALL ON FUNCTION control.partition_health() FROM PUBLIC;" in sql


def test_partition_health_is_kept_out_of_control_sql() -> None:
    """`pack enable` applies control_sql() as whatever role its DSN names, and
    CREATE OR REPLACE FUNCTION fails for anyone but the function's owner."""
    assert "FUNCTION" not in control_sql()


def test_partition_check_names_every_parent_and_raises() -> None:
    sql = partition_check_sql([("raw_wazuh", "alerts"), (None, "mart_fact_wazuh_alerts")])
    assert "format('%I.%I', 'raw_wazuh', 'alerts_' || nxt)" in sql
    assert "format('%I', 'mart_fact_wazuh_alerts_' || nxt)" in sql
    assert "RAISE EXCEPTION" in sql


def test_partition_check_validates_identifiers() -> None:
    with pytest.raises(InvalidIdentifier):
        partition_check_sql([("raw_x'; --", "t")])


# -- the emitter: target order, --all-targets, --all-sources -------------------


def test_default_target_order_is_registration_order(capsys: pytest.CaptureFixture[str]) -> None:
    """incident_lifecycle reads xdr_incidents' mart table, so sorting the
    names alphabetically would emit it first."""
    assert main([]) == 0
    out = capsys.readouterr().out
    positions = [out.index(f"-- {name}\n") for name in TARGETS]
    assert positions == sorted(positions)


def test_all_targets_with_raw_emits_both(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--all-targets", "--raw", "raw_phisher.messages"]) == 0
    out = capsys.readouterr().out
    assert "raw_phisher.messages (raw only, no transform target)" in out
    for target in TARGETS.values():
        assert f"CREATE TABLE IF NOT EXISTS {target.raw_table}" in out


def test_raw_already_created_by_a_target_is_not_repeated(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--all-targets", "--raw", "raw_ksat.enrollments"]) == 0
    out = capsys.readouterr().out
    assert out.count("CREATE TABLE IF NOT EXISTS raw_ksat.enrollments") == 1
    assert "raw_ksat.enrollments (raw only" not in out


def test_all_sources_adds_a_source_that_no_target_reads(
    capsys: pytest.CaptureFixture[str],
) -> None:
    pytest.importorskip("httpx", reason="connectors need the 'http' extra")
    assert main(["--all-targets", "--all-sources"]) == 0
    out = capsys.readouterr().out
    assert "raw_ksat.phishing_runs (raw only, written by source ksat_phishing_runs)" in out
    assert "CREATE TABLE IF NOT EXISTS raw_ksat.phishing_runs" in out


def test_all_sources_names_a_connector_it_cannot_import(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A schema quietly missing one source's table fails that source at its
    first run, so an unimportable connector is a refusal, not a skip."""
    import importlib

    from secops_ingest.schema import __main__ as emitter

    real = importlib.import_module

    def fake(name: str) -> object:
        if name == "secops_ingest.sources.wazuh":
            raise ImportError("No module named 'httpx'")
        return real(name)

    monkeypatch.setattr(emitter.importlib, "import_module", fake)
    assert main(["--all-sources"]) == 1
    err = capsys.readouterr().err
    assert "builtin.wazuh" in err
    assert "httpx" in err


# -- --partitions-only ---------------------------------------------------------


def test_partitions_only_emits_no_tables_control_or_grants(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--target", "wazuh_alerts", "--partitions-only",
                 "--ingest-role", "wh_ingest"]) == 0
    out = capsys.readouterr().out
    assert "CREATE SCHEMA" not in out
    assert "control.ingest_run" not in out
    assert "GRANT" not in out and "REVOKE" not in out
    assert not re.search(r"^CREATE TABLE", out, re.MULTILINE)
    assert "PARTITION OF raw_wazuh.alerts DEFAULT" in out
    assert "PARTITION OF mart_fact_wazuh_alerts DEFAULT" in out


def test_partitions_only_ends_with_the_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--target", "wazuh_alerts", "--raw", "raw_phisher.messages",
                 "--partitions-only"]) == 0
    out = capsys.readouterr().out
    check = out[out.rindex("DO $do$"):]
    assert "RAISE EXCEPTION" in check
    for parent in ("'raw_wazuh', 'alerts_'", "'raw_phisher', 'messages_'",
                   "'mart_fact_wazuh_alerts_'"):
        assert parent in check


def test_partitions_only_skips_unpartitioned_marts(capsys: pytest.CaptureFixture[str]) -> None:
    unpartitioned = [t for t in TARGETS.values()
                     if t.fact_ddl and "PARTITION BY RANGE" not in t.fact_ddl]
    if not unpartitioned:
        pytest.skip("every target's fact table is partitioned")
    t = unpartitioned[0]
    assert main(["--target", t.name, "--partitions-only"]) == 0
    assert f"PARTITION OF {t.fact_table}" not in capsys.readouterr().out


# -- --table-map ---------------------------------------------------------------


def test_table_map_shows_every_target_reading_a_shared_raw_table(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--all-targets", "--raw", "raw_phisher.messages", "--table-map"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc["raw_tables"]["raw_xsoar.incidents"]) == {
        "xsoar_incidents", "incident_lifecycle"
    }
    # A raw table nothing reads is listed with no readers, not left out: a
    # gate must be able to tell "no target" from "not in the map".
    assert doc["raw_tables"]["raw_phisher.messages"] == []
    assert doc["targets"]["wazuh_alerts"]["raw_table"] == "raw_wazuh.alerts"
    assert "sources" not in doc


def test_table_map_with_sources(capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("httpx", reason="connectors need the 'http' extra")
    assert main(["--all-targets", "--all-sources", "--table-map"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["sources"]["ksat_phishing_runs"] == "raw_ksat.phishing_runs"
    assert doc["raw_tables"]["raw_ksat.phishing_runs"] == []


def test_table_map_and_partitions_only_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        main(["--table-map", "--partitions-only"])


# -- role flags on the emitter --------------------------------------------------


def test_full_output_carries_partition_health_and_its_grants(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--target", "wazuh_alerts", "--monitor-role", "lm_monitor"]) == 0
    out = capsys.readouterr().out
    assert out.index("FUNCTION control.partition_health()") < out.index(
        "GRANT EXECUTE ON FUNCTION control.partition_health() TO lm_monitor;"
    )


def test_no_control_means_no_health_function_grant(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--target", "wazuh_alerts", "--no-control", "--monitor-role", "lm"]) == 0
    assert "partition_health" not in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["noschema", ":raw_wazuh", "role:"])
def test_malformed_remote_ingest_role_is_rejected(bad: str) -> None:
    with pytest.raises(SystemExit):
        main(["--remote-ingest-role", bad])


def test_remote_ingest_role_for_a_schema_not_emitted_is_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["--target", "wazuh_alerts", "--remote-ingest-role", "w:raw_xdr"])


def test_remote_and_owner_flags_reach_the_grants(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--target", "wazuh_alerts", "--ingest-role", "wh_ingest",
                 "--remote-ingest-role", "wh_ingest_wazuh:raw_wazuh",
                 "--owner-role", "postgres"]) == 0
    out = capsys.readouterr().out
    assert "GRANT USAGE ON SCHEMA raw_wazuh TO wh_ingest_wazuh;" in out
    assert "REVOKE USAGE ON SCHEMA raw_wazuh FROM wh_ingest;" in out
    assert "FOR ROLE postgres IN SCHEMA raw_wazuh" in out
