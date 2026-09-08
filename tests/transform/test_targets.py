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
from secops_ingest.transform.targets import TARGETS

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
