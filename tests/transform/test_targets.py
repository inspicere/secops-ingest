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
    INCIDENT_LIFECYCLE,
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


def inserted_columns(sql: str) -> list[str]:
    """The INSERT column list, in order."""
    match = re.search(r"INSERT INTO \w+\s*\(([^)]*)\)", body(sql), re.DOTALL)
    assert match, "upsert_sql has no INSERT column list"
    return [c.strip() for c in match.group(1).split(",")]


def updated_columns(sql: str) -> dict[str, str]:
    """DO UPDATE assignments, as {assigned column: EXCLUDED column}."""
    _, _, tail = body(sql).partition("DO UPDATE SET")
    return dict(re.findall(r"(\w+)\s*=\s*EXCLUDED\.(\w+)", tail))


def _split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside parentheses."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        parts.append("".join(current).strip())
    return parts


def selected_expressions(sql: str) -> list[str]:
    """The top-level SELECT expressions of an upsert, in order.

    Everything between the outer SELECT and its own FROM. Subquery FROMs are
    inside parentheses, so tracking depth is enough to find the right one --
    this does not need to be a SQL parser, only good enough to line the SELECT
    list up with the INSERT list positionally.
    """
    text = body(sql)
    start = text.index("SELECT", text.index("INSERT INTO")) + len("SELECT")
    depth = 0
    end = len(text)
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        elif depth == 0 and text.startswith("FROM ", i) and text[i - 1].isspace():
            end = i
            break
    return _split_top_level(text[start:end])


def selected_by_column(sql: str) -> dict[str, str]:
    """{inserted column: the expression that fills it}.

    Substring checks against the whole statement cannot tell which column an
    expression lands in, which is how a column comes to be filled from
    something that merely looks plausible. Pairing the two lists positionally
    is what makes "this column is derived from that side" testable at all.
    """
    columns = inserted_columns(sql)
    expressions = selected_expressions(sql)
    assert len(columns) == len(expressions), (
        f"{len(columns)} columns against {len(expressions)} select expressions")
    return dict(zip(columns, expressions, strict=True))


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
    file path, endpoint) produces a rollup larger than the fact table it
    summarises. Those attributes belong in the facts, where a dashboard can
    filter to one without paying for all of them.
    """
    forbidden = (
        "component_name",
        "agent_name",
        "file_path",
        "title",
        "description",
        "endpoint_id",
        "host_name",
    )
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
def test_do_update_assigns_each_column_from_its_own_excluded_column(
    target: Target,
) -> None:
    """`a = EXCLUDED.b` is accepted by PostgreSQL whenever the types line up.

    Two adjacent text columns swapped in this list produce no error and no
    warning -- just a fact table that is quietly wrong in a way no count
    reveals.
    """
    for assigned, excluded in updated_columns(target.upsert_sql).items():
        assert assigned == excluded, (
            f"{target.name}: {assigned} is refreshed from EXCLUDED.{excluded}")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_do_update_only_refreshes_columns_the_insert_supplies(
    target: Target,
) -> None:
    """EXCLUDED holds the proposed row, so a column absent from the INSERT list
    is refreshed to its default -- usually NULL -- rather than left alone."""
    inserted = set(inserted_columns(target.upsert_sql))
    stray = sorted(set(updated_columns(target.upsert_sql)) - inserted)
    assert not stray, f"{target.name} refreshes columns it never inserts: {stray}"


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_rollup_pair_is_all_or_nothing(target: Target) -> None:
    assert bool(target.rollup_table) == bool(target.rollup_sql)


def test_every_target_is_registered_under_its_own_name() -> None:
    for name, target in TARGETS.items():
        assert target.name == name


def test_every_transform_target_is_registered() -> None:
    """Every Target instance defined at module scope must be in TARGETS.

    An unregistered Target is unreachable code that no scheduler can invoke.

    Lives here rather than in tests/sources/: it touches no connector and no
    HTTP client, and under the module-level importorskip("httpx") over there it
    was silently skipped in any install without the 'http' extra -- including
    the one a reviewer most often has.
    """
    from secops_ingest.transform import targets as targets_module

    defined = {name: obj for name, obj in vars(targets_module).items()
               if isinstance(obj, Target)}
    registered = set(targets_module.TARGETS.values())
    unregistered = sorted(n for n, t in defined.items() if t not in registered)
    assert not unregistered, f"Unregistered transform targets: {unregistered}"


# -- structural invariants the runner and the schema generator depend on ------
#
# R11 was a target whose raw_table was not schema-qualified. Nothing in the
# target definition objected; it failed later, elsewhere, in a generator. These
# are the mechanical checks that would have caught it at the point it was
# written, applied to every target rather than to the one that broke.


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_raw_table_is_schema_qualified(target: Target) -> None:
    """schema/__main__.py partitions raw_table on the dot and rejects it
    otherwise, and runner.py feeds the split to sql.Identifier(*parts) to build
    the watermark query. An unqualified name produces a bare identifier that
    resolves against the search_path -- or nothing at all.
    """
    schema, dot, table = target.raw_table.partition(".")
    assert dot and schema and table, (
        f"{target.name}: raw_table {target.raw_table!r} is not schema-qualified")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_fact_table_is_not_schema_qualified(target: Target) -> None:
    """The mirror image of the rule above, and the reason it is easy to get
    backwards. fact_table goes through validate_identifier, which accepts a
    plain lowercase identifier only -- a dot raises InvalidIdentifier.
    """
    assert "." not in target.fact_table, (
        f"{target.name}: fact_table {target.fact_table!r} must be a bare identifier")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_upsert_reads_the_table_the_target_declares(target: Target) -> None:
    """raw_table is not documentation: the runner takes the watermark and the
    affected-days list from THAT table while the upsert reads whatever its own
    FROM names. If they disagree the two run on different data and the
    watermark advances over rows the upsert never saw.
    """
    assert target.raw_table in body(target.upsert_sql), (
        f"{target.name}: upsert_sql never reads {target.raw_table}")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_the_partition_key_is_in_the_conflict_target(target: Target) -> None:
    """Every fact table here is partitioned on fact_date_expr, and PostgreSQL
    forces the partition key into the primary key. A conflict target that omits
    it has no matching unique index, so the upsert fails at runtime with
    "no unique or exclusion constraint matching the ON CONFLICT specification".

    Deliberately a test and not a check in Target.__post_init__: it holds
    because every target so far partitions on a plain column, which is a
    property of this set of targets rather than of the Target contract.
    """
    _, _, conflict = body(target.upsert_sql).partition("ON CONFLICT")
    conflict = conflict.split(")", 1)[0]
    assert target.fact_date_expr in conflict, (
        f"{target.name}: partition key {target.fact_date_expr} is not in "
        f"ON CONFLICT ({conflict.lstrip(' (')})")


@pytest.mark.parametrize("target", ALL, ids=lambda t: t.name)
def test_the_insert_and_select_lists_are_the_same_length(target: Target) -> None:
    """A column added to one list and not the other is a runtime error at best
    and a silent one-place shift of every following column at worst."""
    assert len(inserted_columns(target.upsert_sql)) == len(
        selected_expressions(target.upsert_sql))


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


def test_xsoar_upsert_refreshes_the_join_key_it_is_indexed_on() -> None:
    """dbotMirrorId is not necessarily set when the incident is created.

    Mirroring is established afterwards, so an incident can land with a NULL
    xdr_incident_id and acquire one later. Omitting the column from DO UPDATE
    froze that NULL for the life of the row -- on the one column this table
    carries a dedicated index for, and the key the whole integration joins on.
    """
    updated = updated_columns(XSOAR_INCIDENTS.upsert_sql)
    for column in ("xdr_incident_id", "incident_type", "source_brand"):
        assert column in updated, f"{column} is never refreshed after first land"


def test_xdr_upsert_refreshes_the_breakdown_with_the_total_it_sums_to() -> None:
    """An incident accrues alerts after it opens.

    Refreshing alert_count while freezing its per-severity components yields a
    row reading alert_count = 10 over a breakdown summing to 3 -- not a stale
    figure but a self-contradictory one, and invisible in either number alone.
    """
    updated = updated_columns(XDR_INCIDENTS.upsert_sql)
    assert "alert_count" in updated
    breakdown = ("high_severity_alert_count", "med_severity_alert_count",
                 "low_severity_alert_count")
    missing = [c for c in breakdown if c not in updated]
    assert not missing, f"alert_count is refreshed without {missing}"
    for column in ("host_count", "user_count", "description"):
        assert column in updated


def test_lifecycle_upsert_refreshes_the_key_behind_its_own_join_status() -> None:
    """join_status is computed from the XDR id, so they are exactly as mutable
    as each other. Updating the verdict but not the key produces rows claiming
    'matched' while carrying nothing to say what they matched.
    """
    updated = updated_columns(INCIDENT_LIFECYCLE.upsert_sql)
    assert "join_status" in updated
    for column in ("xdr_incident_id", "source_brand", "incident_type"):
        assert column in updated


def test_endpoint_target_extracts_the_policy_assignment() -> None:
    """This target's stated purpose is policy health, and it extracted no policy
    column at all -- it could say whether an agent was running, never whether
    the right policy was applied to it. Both fields verified present on the live
    payload 2026-09-14.
    """
    sql = body(XDR_ENDPOINTS.upsert_sql)
    assert "payload->>'assigned_prevention_policy'" in sql
    assert "payload->>'assigned_extensions_policy'" in sql
    for column in ("policy_name", "extensions_policy"):
        assert column in inserted_columns(XDR_ENDPOINTS.upsert_sql)
        assert column in (XDR_ENDPOINTS.fact_ddl or ""), f"{column} has no column"
        # A policy reassignment is the drift this table exists to show, so a
        # re-landed snapshot has to be able to correct it.
        assert column in updated_columns(XDR_ENDPOINTS.upsert_sql)


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
    sql = body(XDR_ALERTS.rollup_sql)
    assert "endpoint_id" not in sql
    assert "host_name" not in sql
    for dim in ("severity", "category", "source"):
        assert dim in sql


def test_alert_rollup_is_rebuilt_from_facts_not_from_raw() -> None:
    """Raw partitions are dropped on schedule; a rollup derived from raw could
    not be rebuilt afterwards."""
    assert "mart_fact_xdr_alerts" in body(XDR_ALERTS.rollup_sql)
    assert "raw_xdr" not in body(XDR_ALERTS.rollup_sql)


def test_endpoint_target_is_keyed_per_snapshot_not_per_endpoint() -> None:
    """A current-state table would overwrite its own history and make drift
    invisible, which is the only thing this source is for."""
    assert "PRIMARY KEY (endpoint_id, snapshot_at)" in body(XDR_ENDPOINTS.fact_ddl)
    assert XDR_ENDPOINTS.fact_date_expr == "snapshot_at"


def test_lifecycle_is_a_left_join_anchored_on_xsoar() -> None:
    """XSOAR holds ~2.75 years against XDR's 325 days. An inner join would
    silently discard every incident older than XDR's retention -- most of them.
    """
    sql = INCIDENT_LIFECYCLE.upsert_sql
    assert "LEFT JOIN" in sql
    assert sql.index("raw_xsoar.incidents") < sql.index("mart_fact_xdr_incidents")


def test_lifecycle_classifies_unmatched_rows_rather_than_hiding_them() -> None:
    """Unmatched rows are two different populations and must not be conflated:
    incidents from a non-XDR feed correctly have no XDR side, while XDR-sourced
    ones that aged out of retention are a data-availability gap.
    """
    sql = INCIDENT_LIFECYCLE.upsert_sql
    for status in ("matched", "non_xdr_source", "xdr_aged_out"):
        assert status in sql
    assert "join_status" in (INCIDENT_LIFECYCLE.fact_ddl or "")


def test_lifecycle_retries_rows_still_waiting_for_their_xdr_side() -> None:
    """The watermark only watches the XSOAR side, so a match can never happen late.

    raw_table is raw_xsoar.incidents, so the incremental predicate is
    `x._ingested_at > since` and a row is re-derived only when its XSOAR raw row
    lands again. This instance auto-closes incidents, so `modified` stops
    advancing and the raw row never re-lands -- an incident whose XDR
    counterpart arrives afterwards would keep a NULL xdr_resolved_at forever.

    `pending_xdr` marks the unmatched-but-still-within-retention rows, and the
    EXISTS arm of the WHERE clause is what re-derives exactly those every run.
    Losing either half silently reinstates the permanent miss.
    """
    sql = body(INCIDENT_LIFECYCLE.upsert_sql)
    # Scoped to the classifying CASE, not to the whole statement. A whole-string
    # search for 'pending_xdr' is satisfied by the retry predicate below, so it
    # would still pass with the CASE branch deleted -- i.e. with the defect
    # fully reinstated.
    case = sql[sql.index("CASE"):sql.index("END")]
    for status in ("matched", "non_xdr_source", "pending_xdr", "xdr_aged_out"):
        assert f"'{status}'" in case, f"join_status {status} is not produced"
    # The retry arm: an EXISTS back against this target's own fact table,
    # restricted to the non-terminal state. Without it `pending_xdr` is just a
    # relabelled `xdr_aged_out` that is still never revisited.
    assert "EXISTS (" in sql
    assert "FROM mart_fact_incident_lifecycle l" in sql
    assert "l.join_status = 'pending_xdr'" in sql


def test_lifecycle_pending_state_is_bounded_by_xdr_retention() -> None:
    """`pending_xdr` must be self-limiting or the retry set grows without bound.

    The 325-day horizon is XDR's retention: past it the XDR record genuinely
    cannot arrive, the row becomes a terminal `xdr_aged_out`, and it drops out
    of the retry set for good.
    """
    sql = body(INCIDENT_LIFECYCLE.upsert_sql)
    assert "interval '325 days'" in sql
    # The pending branch must be tried BEFORE the aged-out fallback, or every
    # in-retention row falls straight through to the terminal state.
    assert sql.index("'pending_xdr'") < sql.index("'xdr_aged_out'")


def test_lifecycle_takes_one_xdr_row_per_incident() -> None:
    """A plain LEFT JOIN fans out if the XDR fact ever holds two partitions for
    one incident_id, and a fan-out here multiplies the row it is joined to.

    The fact table is partitioned on created_at and keyed
    (incident_id, created_at), so one id CAN legitimately hold more than one
    row. The LATERAL picks the newest and caps the join at one.
    """
    sql = body(INCIDENT_LIFECYCLE.upsert_sql)
    assert "LEFT JOIN LATERAL" in sql
    assert "ORDER BY i.created_at DESC" in sql
    assert "LIMIT 1" in sql


def test_lifecycle_measures_resolution_from_the_xsoar_side() -> None:
    """The same incident exists on both sides; measuring it twice double-counts.

    This asserts the DERIVATION, not the presence of the column names. The
    obvious version -- "closed_at appears in the SQL" -- passes just as happily
    when closed_at is filled from d.resolved_at, which is the exact
    mis-sourcing this test is named for: the XDR side resolves when detection
    closes it, the XSOAR side when the response actually finished, and the two
    are different numbers.
    """
    assert "time_to_resolve" in (INCIDENT_LIFECYCLE.fact_ddl or "")
    selected = selected_by_column(INCIDENT_LIFECYCLE.upsert_sql)

    closed = selected["closed_at"]
    assert "x.payload->>'closed'" in closed
    assert "d." not in closed, f"closed_at is taken from the XDR side: {closed}"

    ttr = selected["time_to_resolve"]
    assert "x.payload->>'closed'" in ttr
    assert "- (x.payload->>'created')::timestamptz" in ttr, (
        f"time_to_resolve does not subtract the XSOAR created time: {ttr}")
    assert "d." not in ttr, f"time_to_resolve reaches into the XDR side: {ttr}"

    # The XDR timestamps still land, in their own columns, so the two sides can
    # be compared -- they just do not feed the XSOAR-side measure.
    assert selected["xdr_created_at"] == "d.created_at"
    assert selected["xdr_resolved_at"] == "d.resolved_at"


def test_lifecycle_filters_on_the_anchor_tables_ingested_at() -> None:
    """The runner interpolates raw_table as a live SQL identifier to fetch
    _ingested_at and _event_time. Fact tables carry no _ingested_at, so
    raw_xsoar.incidents must be the raw_table, and the incremental predicate
    must use its _ingested_at column.
    """
    assert INCIDENT_LIFECYCLE.raw_table == "raw_xsoar.incidents"
    assert "x._ingested_at > %(since)s::timestamptz" in INCIDENT_LIFECYCLE.upsert_sql
