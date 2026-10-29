"""control.source_state, its hold-out functions and control.source_freshness, as text.

Audit V-18: a pack DISABLED or a deployment hold-out left no trace, and a
transform over stale raw reported SUCCESS. These pin what the emitted SQL
promises; tests/schema/test_source_state_integration.py proves PostgreSQL
keeps those promises.
"""

from __future__ import annotations

import re

import pytest

from secops_ingest.schema import (
    SOURCE_FRESHNESS_COLUMNS,
    SOURCE_STATE_FUNCTIONS,
    InvalidIdentifier,
    control_sql,
    control_tables,
    grants_sql,
    source_freshness_sql,
    source_state_sql,
)
from secops_ingest.schema.__main__ import main


def _code(sql: str) -> str:
    """`sql` without its -- comment lines, which name these objects freely."""
    return "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))


def g(**kw: object) -> str:
    return grants_sql(["raw_wazuh"], ["mart_fact_wazuh_alerts"], **kw)  # type: ignore[arg-type]


# -- the table ----------------------------------------------------------------


def test_control_creates_source_state_keyed_by_source_and_origin() -> None:
    assert "source_state" in control_tables()
    body = control_sql().split("CREATE TABLE IF NOT EXISTS control.source_state", 1)[1]
    body = body.split(");", 1)[0]
    assert "PRIMARY KEY (source, origin)" in body
    assert "CHECK (origin IN ('pack','deploy'))" in body
    # A pack row can only be DISABLED and a deploy row only HELD_OUT, so the
    # two origins cannot impersonate each other.
    assert "CASE origin WHEN 'pack' THEN 'DISABLED' ELSE 'HELD_OUT' END" in body


def test_no_worker_may_write_source_state_directly() -> None:
    """Owner writes; workers only through the definer functions. A grant
    cannot say which rows, and the pack rows must stay the owner's."""
    sql = g(ingest_role="i", transform_role="t", read_role="m", monitor_role="lm",
            source_state=True)
    assert "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.source_state FROM i;" in sql
    assert "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.source_state FROM t;" in sql
    assert not re.search(r"GRANT [A-Z, ]*(INSERT|UPDATE)[A-Z, ]* ON control\.source_state", sql)


# -- the hold-out functions ----------------------------------------------------


def test_hold_out_functions_are_definer_with_a_pinned_search_path() -> None:
    sql = _code(source_state_sql())
    assert sql.count("SECURITY DEFINER") == 2
    assert sql.count("SET search_path = pg_catalog, pg_temp") == 2
    for fn in SOURCE_STATE_FUNCTIONS:
        assert f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC;" in sql


def test_hold_out_functions_only_touch_deploy_rows_and_record_the_login() -> None:
    sql = _code(source_state_sql())
    assert "'pack'" not in sql
    assert "origin = 'deploy'" in sql
    # session_user, not current_user: inside a definer function current_user
    # is the owner, and every row would claim the owner held it out.
    assert "session_user" in sql
    assert "current_user" not in sql


def test_hold_out_functions_are_not_in_control_sql() -> None:
    """`pack enable` applies control_sql() as whoever its DSN names, and
    CREATE OR REPLACE FUNCTION needs the owner."""
    assert "hold_out_source" not in _code(control_sql())


def test_only_ingest_roles_may_execute_the_hold_out_functions() -> None:
    sql = grants_sql(
        ["raw_wazuh", "raw_xdr"], [], ingest_role="i", transform_role="t", read_role="m",
        monitor_role="lm", remote_ingest=[("rw", "raw_wazuh")], source_state=True,
    )
    for fn in SOURCE_STATE_FUNCTIONS:
        assert f"GRANT EXECUTE ON FUNCTION {fn} TO i;" in sql
        assert f"GRANT EXECUTE ON FUNCTION {fn} TO rw;" in sql
        for role in ("t", "m", "lm"):
            assert f"GRANT EXECUTE ON FUNCTION {fn} TO {role};" not in sql


def test_hold_out_grants_only_when_the_functions_are_emitted() -> None:
    assert "hold_out_source" not in g(ingest_role="i")


# -- the view -------------------------------------------------------------------


MAPPING = [
    ("defectdojo", "builtin", ["defectdojo_findings"]),
    ("xsoar", "builtin", ["xsoar_incidents", "incident_lifecycle"]),
    ("ksat_phishing_runs", "builtin", []),
]


def test_view_carries_one_row_per_source_and_target() -> None:
    sql = source_freshness_sql(MAPPING)
    assert "('defectdojo'::text, 'builtin'::text, 'defectdojo_findings'::text)" in sql
    assert "('xsoar'::text, 'builtin'::text, 'incident_lifecycle'::text)" in sql
    assert "('xsoar'::text, 'builtin'::text, 'xsoar_incidents'::text)" in sql
    # A source no target reads still gets its row, with a NULL target.
    assert "('ksat_phishing_runs'::text, 'builtin'::text, NULL::text)" in sql


def test_view_with_no_mapping_is_still_valid_sql_shape() -> None:
    sql = source_freshness_sql([])
    assert "SELECT NULL::text, NULL::text, NULL::text WHERE false" in sql
    assert "VALUES\n" not in sql.split("ingest AS")[0]


@pytest.mark.parametrize(
    "mapping",
    [
        [("x'; DROP TABLE control.pack; --", "builtin", [])],
        [("ok", "Bad-Pack", [])],
        [("ok", "builtin", ["t' OR '1"])],
    ],
)
def test_view_refuses_names_it_would_have_to_quote(
    mapping: list[tuple[str, str, list[str]]],
) -> None:
    with pytest.raises(InvalidIdentifier):
        source_freshness_sql(mapping)


def test_view_columns_are_the_published_interface_in_order() -> None:
    sql = source_freshness_sql(MAPPING)
    select = sql.rsplit("\nSELECT ", 1)[1]
    aliases = re.findall(r"(?:AS (\w+)|^\s*(\w+),?$)", select, re.MULTILINE)
    names = [a or b for a, b in aliases if (a or b) != "FROM"]
    assert tuple(names) == SOURCE_FRESHNESS_COLUMNS


def test_never_is_handled_explicitly_not_through_least() -> None:
    """least() ignores NULL: least(ingest, never) would report the ingest time
    and hide a target that never succeeded. as_of must be NULL then."""
    sql = source_freshness_sql(MAPPING)
    assert "WHEN cardinality(never_succeeded) > 0 THEN NULL" in sql
    assert "FILTER (WHERE status = 'SUCCESS')" in sql


def test_view_is_create_or_replace_so_reapplying_keeps_grants() -> None:
    assert "CREATE OR REPLACE VIEW control.source_freshness AS" in source_freshness_sql([])


# -- the emitter ------------------------------------------------------------------


def test_emitter_includes_functions_and_view_with_all_sources(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--all-targets", "--all-sources", "--ingest-role", "wh_ingest",
                 "--read-role", "wh_metabase"]) == 0
    out = capsys.readouterr().out
    assert "CREATE OR REPLACE FUNCTION control.hold_out_source" in out
    assert "CREATE OR REPLACE VIEW control.source_freshness" in out
    # Mapped through the raw table the connector declares.
    assert "('defectdojo'::text, 'builtin'::text, 'defectdojo_findings'::text)" in out
    assert "('xsoar'::text, 'builtin'::text, 'incident_lifecycle'::text)" in out
    assert "GRANT EXECUTE ON FUNCTION control.hold_out_source(text, text) TO wh_ingest;" in out
    assert "TO wh_metabase;" in out
    assert "EXECUTE ON FUNCTION control.hold_out_source(text, text) TO wh_metabase" not in out
    # Grants after the view, or SELECT ON ALL TABLES would miss it.
    assert out.index("CREATE OR REPLACE VIEW control.source_freshness") < out.index(
        "GRANT SELECT ON ALL TABLES IN SCHEMA control TO wh_metabase;"
    )


def test_emitter_maps_only_the_targets_it_emits(capsys: pytest.CaptureFixture[str]) -> None:
    """A target the deployment does not run would hold its source at "never"."""
    assert main(["--target", "xsoar_incidents", "--all-sources"]) == 0
    out = capsys.readouterr().out
    assert "('xsoar'::text, 'builtin'::text, 'xsoar_incidents'::text)" in out
    assert "incident_lifecycle'::text)" not in out


def test_emitter_without_all_sources_leaves_the_view_out_and_says_why(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "CREATE OR REPLACE VIEW control.source_freshness" not in out
    assert "control.source_freshness is emitted only with --all-sources" in out
    # The table and functions need no mapping, so they are always there.
    assert "CREATE TABLE IF NOT EXISTS control.source_state" in out
    assert "CREATE OR REPLACE FUNCTION control.release_source" in out


def test_no_control_means_none_of_it(capsys: pytest.CaptureFixture[str]) -> None:
    # The per-table control REVOKEs are still emitted, as for every control
    # table; what --no-control leaves out is creating anything.
    assert main(["--no-control", "--all-sources", "--ingest-role", "i"]) == 0
    out = capsys.readouterr().out
    assert "CREATE TABLE IF NOT EXISTS control.source_state" not in out
    assert "source_freshness" not in out
    assert "hold_out_source" not in out


def test_partitions_only_output_never_touches_source_state(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--all-targets", "--all-sources", "--partitions-only"]) == 0
    out = capsys.readouterr().out
    assert "source_state" not in out
    assert "source_freshness" not in out
