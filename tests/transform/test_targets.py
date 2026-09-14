"""Guards for the transform targets.

These do not re-state the SQL. Each one pins a decision that is easy to undo by
accident and whose failure mode is silent — a rollup that quietly grows larger
than its fact table, an average that is wrong only when aggregated, a number
that is correct on the day it is written and drifts afterwards.
"""

from __future__ import annotations

import re

import pytest

from secops_ingest.transform.base import Target
from secops_ingest.transform.targets import (
    TARGETS,
    XDR_ALERTS,
    XDR_ENDPOINTS,
    XDR_INCIDENTS,
    XSOAR_INCIDENTS,
)

ALL = list(TARGETS.values())
WITH_ROLLUP = [t for t in ALL if t.rollup_table]

_COMMENT = re.compile(r"--[^\n]*")


def body(sql: str | None) -> str:
    """SQL with line comments stripped.

    These guards scan for tokens, and the comments explaining WHY a token is
    forbidden contain that very token. Scanning the raw string makes a correct
    target fail on its own documentation -- which is how a guard gets deleted.
    """
    return _COMMENT.sub("", sql or "")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_upsert_is_incremental(target: Target) -> None:
    """Without the watermark parameter every run reprocesses the whole raw table."""
    assert "%(since)s" in target.upsert_sql


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_watermark_parameter_is_cast(target: Target) -> None:
    """PostgreSQL cannot infer a type for a bare parameter inside IS NULL.

    It raises AmbiguousParameter at execution time, so an uncast target looks
    fine until the first run.
    """
    if "IS NULL" in target.upsert_sql:
        assert "%(since)s::timestamptz IS NULL" in target.upsert_sql


@pytest.mark.parametrize("target", WITH_ROLLUP, ids=lambda t: t.name)
def test_rollup_reads_facts_not_raw(target: Target) -> None:
    """Rollups must stay rebuildable after raw has been dropped.

    Raw is a bounded re-derivation buffer; the reporting layer outlives it. A
    rollup sourced from raw silently stops being reproducible the day the
    partition expires.
    """
    assert target.raw_table not in body(target.rollup_sql)
    assert target.fact_table in body(target.rollup_sql)


@pytest.mark.parametrize("target", WITH_ROLLUP, ids=lambda t: t.name)
def test_rollup_has_no_high_cardinality_dimension(target: Target) -> None:
    """The rule the WAZUH target documents, enforced rather than described.

    A dimension bounded only by the size of the estate (component, agent, host,
    file path) produces a rollup larger than the fact table it summarises. Those
    attributes belong in the facts, where a dashboard can filter to one without
    paying for all of them.
    """
    forbidden = ("component_name", "agent_name", "file_path", "title", "description")
    sql = body(target.rollup_sql).lower()
    offenders = [c for c in forbidden if c in sql]
    assert not offenders, f"{target.name} rollup groups on {offenders}"


@pytest.mark.parametrize("target", WITH_ROLLUP, ids=lambda t: t.name)
def test_rollup_stores_additive_measures_only(target: Target) -> None:
    """Averages do not re-aggregate.

    Averaging daily averages over a month weights a day with two findings the
    same as a day with two hundred. Store SUM and COUNT and divide at the grain
    actually being displayed.
    """
    sql = body(target.rollup_sql).upper()
    assert not re.search(r"\bAVG\s*\(", sql), f"{target.name} stores a mean"


@pytest.mark.parametrize("target", WITH_ROLLUP, ids=lambda t: t.name)
def test_rollup_is_not_a_function_of_wall_clock_time(target: Target) -> None:
    """A rollup is recomputed only when its underlying rows change.

    Anything derived from the current time is therefore correct on the day it is
    written and drifts wrong every day after, with nothing to trigger a
    recompute. "Is this open finding past its SLA?" is that kind of question and
    must be answered at query time against the facts.
    """
    sql = body(target.rollup_sql).lower()
    for token in ("now()", "current_date", "current_timestamp"):
        assert token not in sql, f"{target.name} rollup depends on {token}"


def test_defectdojo_counts_only_settled_sla_breaches() -> None:
    """Breach is counted on close, which is a fact that cannot change again."""
    sql = body(TARGETS["defectdojo_findings"].rollup_sql)
    assert "mitigated_at IS NOT NULL" in sql
    assert "mitigated_at::date > sla_expiration_date" in sql


def test_defectdojo_status_precedence_puts_false_positive_first() -> None:
    """A finding can be several states at once and the first CASE branch wins.

    A false positive that was also closed must not be counted as a mitigation,
    or time-to-mitigate takes credit for work nobody did.
    """
    sql = body(TARGETS["defectdojo_findings"].upsert_sql)
    assert sql.index("false_p") < sql.index("is_mitigated")


def test_defectdojo_grain_is_discovery_not_modification() -> None:
    """Discovery date is immutable; modification date is not.

    A modification-date grain would scatter one finding's history across every
    day somebody touched it, and the partition key would move with each edit.
    """
    t = TARGETS["defectdojo_findings"]
    assert t.fact_date_expr == "discovered_at"
    assert "last_status_update" not in t.fact_date_expr


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_rollup_pair_is_all_or_nothing(target: Target) -> None:
    assert bool(target.rollup_table) == bool(target.rollup_sql)


def test_every_target_is_registered_under_its_own_name() -> None:
    for name, target in TARGETS.items():
        assert target.name == name


def test_xsoar_target_partitions_on_created_and_upserts_on_the_partition_key() -> None:
    t = XSOAR_INCIDENTS
    assert t.raw_table == "raw_xsoar.incidents"
    assert t.fact_date_expr == "created_at"
    # Partitioned tables force the partition key into the primary key, so it
    # must appear in the conflict target or the upsert fails at runtime.
    assert "ON CONFLICT (incident_id, created_at)" in t.upsert_sql


def test_xsoar_target_carries_the_xdr_join_key() -> None:
    """dbotMirrorId is the XDR incident id. Without it there is no lifecycle.

    These are substring assertions and do not verify positional correspondence
    between the INSERT column list and the SELECT expressions — a SQL parser
    would be needed for that. They catch obvious omissions and renamed fields,
    but not a field selected into the wrong column. That level of verification
    is not worth the parsing complexity here.
    """
    assert "payload->>'dbotMirrorId'" in XSOAR_INCIDENTS.upsert_sql
    assert "xdr_incident_id" in XSOAR_INCIDENTS.fact_ddl


def test_xsoar_target_guards_the_open_incident_sentinel() -> None:
    """No open incident existed to sample, so every plausible representation of
    "not closed" must be treated as open -- absent, empty, or the Go zero time.
    A missed guard makes an open incident report a resolution time of roughly
    minus two thousand years and poisons every average built on it.
    """
    sql = XSOAR_INCIDENTS.upsert_sql
    # Assert all three guards explicitly. A partial regression dropping one of
    # them would pass a simpler test, but these three checks catch it.
    assert "NULLIF(NULLIF" in sql  # Nested guard for absent and empty string
    assert "NULLIF(payload->>'closed', '')" in sql  # Empty string guard
    assert "'0001-01-01T00:00:00Z'" in sql  # Go zero time guard


def test_xsoar_target_reads_status_and_severity_as_integers() -> None:
    """Measured: status and severity are ints (status=2 for closed), not the
    strings the original runbook assumed."""
    assert "(payload->>'status')::int" in XSOAR_INCIDENTS.upsert_sql
    assert "(payload->>'severity')::int" in XSOAR_INCIDENTS.upsert_sql


def test_xdr_target_divides_epoch_milliseconds() -> None:
    """Miss the /1000 and every incident lands in the year 56,000.

    There are three epoch conversions (creation_time, modification_time,
    resolved_timestamp). A partial regression dropping the division on one or
    two of them would pass a simpler test; this count catches partial misses.
    """
    assert XDR_INCIDENTS.upsert_sql.count("/ 1000") == 3
    assert XDR_INCIDENTS.fact_date_expr == "created_at"


def test_both_incident_targets_select_on_ingested_at() -> None:
    """The transform asks "what landed since my watermark", which for a
    mutating source includes rows whose event time is months old."""
    for t in (XSOAR_INCIDENTS, XDR_INCIDENTS):
        assert "_ingested_at > %(since)s::timestamptz" in t.upsert_sql


def test_alerts_target_has_a_rollup_because_the_volume_requires_one() -> None:
    """~17.7k alerts/day is ~6.5M rows/year. A seven-year trend over per-record
    facts is unusable on a modest host."""
    assert XDR_ALERTS.rollup_table == "mart_rollup_xdr_alerts_daily"
    assert XDR_ALERTS.rollup_sql is not None


def test_alert_rollup_dimensions_are_all_low_cardinality() -> None:
    """endpoint_id is the tempting mistake: 1,630 endpoints would make the
    rollup larger than the fact table it summarises."""
    sql = XDR_ALERTS.rollup_sql or ""
    assert "endpoint_id" not in sql
    assert "host_name" not in sql
    for dim in ("severity", "category", "source"):
        assert dim in sql


def test_alert_rollup_is_rebuilt_from_facts_not_from_raw() -> None:
    """Raw partitions are dropped on schedule; a rollup derived from raw could
    not be rebuilt afterwards."""
    assert "mart_fact_xdr_alerts" in (XDR_ALERTS.rollup_sql or "")
    assert "raw_xdr" not in (XDR_ALERTS.rollup_sql or "")


def test_endpoint_target_is_keyed_per_snapshot_not_per_endpoint() -> None:
    """A current-state table would overwrite its own history and make drift
    invisible, which is the only thing this source is for."""
    assert "PRIMARY KEY (endpoint_id, snapshot_at)" in (
        XDR_ENDPOINTS.fact_ddl or ""
    )
    assert XDR_ENDPOINTS.fact_date_expr == "snapshot_at"
