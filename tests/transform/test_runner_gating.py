"""The runner's staleness guard, tested without a database.

WHY THIS FILE EXISTS.

`runner.execute` had no test coverage, and its guard silently defeated a
correctness fix. The fix was a predicate inside a target's `upsert_sql`; the
guard decides whether that statement is executed at all. Reviewing the SQL --
which three separate reviews did -- cannot reveal that it never runs. Verified
against PostgreSQL 16: the run recorded `rows_upserted=0` and the upsert was
never executed.

So the decision is extracted and tested here, for exactly the reason
`common/watermark.py` is extracted: it is where a silent data-loss defect lived,
and it must be checkable without a driver.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secops_ingest.transform.base import Target, effective_since, should_skip
from secops_ingest.transform.targets import TARGETS

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
EARLIER = NOW - timedelta(hours=1)


def make(**kw: object) -> Target:
    base: dict[str, object] = {
        "name": "t",
        "raw_table": "raw_x.things",
        "fact_table": "mart_fact_t",
        "fact_date_expr": "created_at",
        "upsert_sql": ("INSERT INTO mart_fact_t SELECT 1 FROM raw_x.things "
                       "WHERE %(since)s::timestamptz IS NULL "
                       "OR _ingested_at > %(since)s::timestamptz"),
    }
    base.update(kw)
    return Target(**base)  # type: ignore[arg-type]


# -- the ordinary, incremental case ------------------------------------------

def test_incremental_target_is_skipped_when_raw_has_not_moved() -> None:
    assert should_skip(make(), since=NOW, new_mark=EARLIER) is True


def test_incremental_target_is_skipped_when_the_mark_equals_the_watermark() -> None:
    """`<=`, not `<`: re-running on an unchanged mark is pure waste."""
    assert should_skip(make(), since=NOW, new_mark=NOW) is True


def test_incremental_target_runs_when_raw_has_moved() -> None:
    assert should_skip(make(), since=EARLIER, new_mark=NOW) is False


def test_incremental_target_runs_on_a_first_run() -> None:
    assert should_skip(make(), since=None, new_mark=NOW) is False


def test_incremental_target_is_skipped_when_raw_is_empty() -> None:
    assert should_skip(make(), since=None, new_mark=None) is True


# -- the full-refresh case: this is the regression ---------------------------

def test_full_refresh_target_runs_even_when_raw_has_not_moved() -> None:
    """THE REGRESSION.

    A join target's second input changes while `raw_table` sits untouched. Under
    the old guard this returned True, the upsert never executed, and rows that
    needed re-deriving were stranded permanently -- with the fix for that very
    problem sitting unreachable inside the SQL.
    """
    assert should_skip(make(full_refresh=True), since=NOW, new_mark=EARLIER) is False


def test_full_refresh_target_runs_when_the_mark_equals_the_watermark() -> None:
    assert should_skip(make(full_refresh=True), since=NOW, new_mark=NOW) is False


def test_full_refresh_target_runs_even_against_empty_raw() -> None:
    assert should_skip(make(full_refresh=True), since=NOW, new_mark=None) is False


# -- what gets bound to %(since)s --------------------------------------------

def test_full_refresh_binds_null_so_the_upsert_re_derives_everything() -> None:
    """The upsert's `%(since)s::timestamptz IS NULL` branch is the full path."""
    assert effective_since(make(full_refresh=True), NOW) is None


def test_incremental_binds_the_watermark_unchanged() -> None:
    assert effective_since(make(), NOW) is NOW


# -- which real targets opt in -----------------------------------------------

def test_full_refresh_defaults_off() -> None:
    """A new target must not silently inherit a full re-derive."""
    assert make().full_refresh is False


def test_only_the_lifecycle_join_opts_into_full_refresh() -> None:
    """Every other target is source-shaped: its raw_table IS its only input, so
    the watermark can see all of its work and a full refresh would be waste."""
    opted = {n for n, t in TARGETS.items() if t.full_refresh}
    assert opted == {"incident_lifecycle"}


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_every_target_still_declares_the_since_parameter(name: str) -> None:
    """full_refresh binds it to NULL rather than removing it, so the branch the
    upsert takes on a full refresh must still exist."""
    assert "%(since)s" in TARGETS[name].upsert_sql
