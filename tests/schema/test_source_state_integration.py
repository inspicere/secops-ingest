"""control.source_state, the hold-out functions and control.source_freshness on PostgreSQL.

tests/schema/test_source_state.py pins the emitted text; this file proves it
means what it claims (audit V-18): the ingest role can record and release its
own hold-outs and nothing else, the pack rows stay the owner's, the view
reports the older of ingest and transform success with "never" as NULL, and a
warehouse without any of it runs dim rather than refusing.

Skipped unless SECOPS_TEST_DSN is set, matching the other integration files.
The DSN must be a superuser: it creates throwaway roles, all prefixed
`secops_t_ss_`, and impersonates them with SET SESSION AUTHORIZATION, which is
what makes session_user -- the login the functions record -- differ per test::

    SECOPS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:5433/secops \\
        pytest tests/schema/test_source_state_integration.py -v
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

from secops_ingest import holdout  # noqa: E402
from secops_ingest.builtin import PACK as BUILTIN  # noqa: E402
from secops_ingest.common import schema_check  # noqa: E402
from secops_ingest.packs.__main__ import main as packs_main  # noqa: E402
from secops_ingest.schema import (  # noqa: E402
    control_sql,
    grants_sql,
    partition_health_sql,
    source_freshness_sql,
    source_state_sql,
)
from tests.packs.test_state_integration import _refuse_if_live  # noqa: E402

INGEST, OTHER, TRANSFORM, READ, MONITOR = (
    "secops_t_ss_ingest", "secops_t_ss_other", "secops_t_ss_transform",
    "secops_t_ss_read", "secops_t_ss_monitor",
)
ROLES = (INGEST, OTHER, TRANSFORM, READ, MONITOR)

MAPPING = [
    ("defectdojo", "builtin", ["defectdojo_findings"]),
    ("xsoar", "builtin", ["incident_lifecycle", "xsoar_incidents"]),
    ("ksat_phishing_runs", "builtin", []),
    ("wazuh", "builtin", ["wazuh_alerts"]),
]


def _drop_everything(conn: psycopg.Connection) -> None:
    conn.execute("RESET SESSION AUTHORIZATION")
    for schema in ("control", "raw_wazuh"):
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    for role in ROLES:
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            conn.execute(f"DROP OWNED BY {role}")
            conn.execute(f"DROP ROLE {role}")


@pytest.fixture()
def warehouse() -> Iterator[psycopg.Connection]:
    """control with the V-18 objects, the five roles, the generated grants.

    Autocommit, so a refused statement leaves nothing aborted and the next
    probe in the same test runs as normal.
    """
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"], autocommit=True) as conn:
        _refuse_if_live(conn)
        _drop_everything(conn)
        for role in ROLES:
            conn.execute(f"CREATE ROLE {role}")
        conn.execute("CREATE SCHEMA raw_wazuh")
        conn.execute(control_sql())
        conn.execute(partition_health_sql())
        conn.execute(source_state_sql())
        conn.execute(source_freshness_sql(MAPPING))
        conn.execute(grants_sql(
            ["raw_wazuh"], [], ingest_role=INGEST, transform_role=TRANSFORM,
            read_role=READ, monitor_role=MONITOR, remote_ingest=[(OTHER, "raw_wazuh")],
            partition_health=True, source_state=True,
        ))
        try:
            yield conn
        finally:
            _drop_everything(conn)


@contextmanager
def login(conn: psycopg.Connection, role: str) -> Iterator[None]:
    """Run as if `role` had logged in: session_user and current_user both."""
    conn.execute(f"SET SESSION AUTHORIZATION {role}")
    try:
        yield
    finally:
        conn.execute("RESET SESSION AUTHORIZATION")


def _one(conn: psycopg.Connection, statement: str, params: tuple[Any, ...] = ()) -> Any:
    row = conn.execute(statement, params).fetchone()
    assert row is not None
    return row[0]


def _row(conn: psycopg.Connection, source: str, origin: str = "deploy") -> tuple[Any, ...] | None:
    row: tuple[Any, ...] | None = conn.execute(
        "SELECT state, reason, changed_at, changed_by FROM control.source_state "
        "WHERE source = %s AND origin = %s", (source, origin),
    ).fetchone()
    return row


def _fresh(conn: psycopg.Connection, source: str) -> dict[str, Any]:
    cur = conn.execute("SELECT * FROM control.source_freshness WHERE source = %s", (source,))
    row = cur.fetchone()
    assert row is not None, source
    assert cur.description is not None
    return {d.name: v for d, v in zip(cur.description, row, strict=True)}


def _ingest(conn: psycopg.Connection, source: str, status: str, hours_ago: float) -> None:
    conn.execute(
        "INSERT INTO control.ingest_run (source, status, started_at, ended_at) "
        "VALUES (%s, %s, now() - make_interval(secs => %s), now() - make_interval(secs => %s))",
        (source, status, hours_ago * 3600 + 60, hours_ago * 3600),
    )


def _transform(conn: psycopg.Connection, target: str, status: str, hours_ago: float) -> None:
    conn.execute(
        "INSERT INTO control.transform_run (target, status, started_at, ended_at) "
        "VALUES (%s, %s, now() - make_interval(secs => %s), now() - make_interval(secs => %s))",
        (target, status, hours_ago * 3600 + 60, hours_ago * 3600),
    )


HOLD = "SELECT control.hold_out_source(%s, %s)"
RELEASE = "SELECT control.release_source(%s)"


# -- who may write what ---------------------------------------------------------


def test_ingest_holds_out_through_the_function_and_the_row_names_the_login(
    warehouse: psycopg.Connection,
) -> None:
    with login(warehouse, INGEST):
        assert _one(warehouse, HOLD, ("xdr_alerts", "listed in ingest_disabled_sources"))
    state, reason, _at, by = _row(warehouse, "xdr_alerts") or ()
    assert (state, reason, by) == ("HELD_OUT", "listed in ingest_disabled_sources", INGEST)


def test_reasserting_the_same_hold_out_changes_nothing(warehouse: psycopg.Connection) -> None:
    """A converge re-asserts every run; changed_at must keep meaning when the
    state changed, and the call must say "no change" for changed_when."""
    with login(warehouse, INGEST):
        assert _one(warehouse, HOLD, ("xdr_alerts", "r"))
        first = _row(warehouse, "xdr_alerts")
        assert not _one(warehouse, HOLD, ("xdr_alerts", "r"))
        assert _row(warehouse, "xdr_alerts") == first
        assert _one(warehouse, HOLD, ("xdr_alerts", "a new reason"))


def test_ingest_cannot_write_the_table_directly(warehouse: psycopg.Connection) -> None:
    with login(warehouse, INGEST):
        for statement in (
            "INSERT INTO control.source_state (source, origin, state) "
            "VALUES ('x', 'deploy', 'HELD_OUT')",
            "UPDATE control.source_state SET state = 'ACTIVE'",
            "DELETE FROM control.source_state",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                warehouse.execute(statement)


def test_ingest_cannot_clear_a_pack_disable(warehouse: psycopg.Connection) -> None:
    warehouse.execute(
        "INSERT INTO control.source_state (source, origin, state, reason) "
        "VALUES ('wazuh', 'pack', 'DISABLED', 'pack builtin disabled')"
    )
    with login(warehouse, INGEST):
        assert not _one(warehouse, RELEASE, ("wazuh",))
        assert _one(warehouse, HOLD, ("wazuh", "also held out"))
    assert (_row(warehouse, "wazuh", "pack") or ())[0] == "DISABLED"
    assert _fresh(warehouse, "wazuh")["state"] == "DISABLED"


def test_release_is_own_rows_only(warehouse: psycopg.Connection) -> None:
    with login(warehouse, OTHER):
        assert _one(warehouse, HOLD, ("wazuh", "enclave-01 holds it"))
    with login(warehouse, INGEST):
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match=f"held out by {OTHER}"):
            warehouse.execute(RELEASE, ("wazuh",))
    assert (_row(warehouse, "wazuh") or ())[0] == "HELD_OUT"
    with login(warehouse, OTHER):
        assert _one(warehouse, RELEASE, ("wazuh",))
    state, reason, _at, by = _row(warehouse, "wazuh") or ()
    # Kept as ACTIVE, not deleted: who released it and when stays visible.
    assert (state, reason, by) == ("ACTIVE", None, OTHER)


def test_releasing_nothing_is_false_not_an_error(warehouse: psycopg.Connection) -> None:
    with login(warehouse, INGEST):
        assert not _one(warehouse, RELEASE, ("never_held",))


@pytest.mark.parametrize(
    ("source", "reason"),
    [("xdr_alerts", ""), ("xdr_alerts", "   "), ("xdr_alerts", "x" * 501),
     ("Bad-Name", "r"), (None, "r")],
)
def test_a_hold_out_needs_a_name_and_a_reason(
    warehouse: psycopg.Connection, source: str | None, reason: str
) -> None:
    with login(warehouse, INGEST):
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            warehouse.execute(HOLD, (source, reason))


@pytest.mark.parametrize("role", [TRANSFORM, READ, MONITOR])
def test_only_ingest_roles_may_hold_out(warehouse: psycopg.Connection, role: str) -> None:
    with login(warehouse, role):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            warehouse.execute(HOLD, ("xdr_alerts", "r"))


@pytest.mark.parametrize("role", [READ, MONITOR, TRANSFORM, INGEST])
def test_every_role_with_control_read_can_read_the_view(
    warehouse: psycopg.Connection, role: str
) -> None:
    with login(warehouse, role):
        assert _one(warehouse, "SELECT count(*) FROM control.source_freshness") == len(MAPPING)


# -- what the view says ------------------------------------------------------------


def test_freshness_is_the_older_of_ingest_and_transform_success(
    warehouse: psycopg.Connection,
) -> None:
    _ingest(warehouse, "defectdojo", "SUCCESS", 1)
    _transform(warehouse, "defectdojo_findings", "SUCCESS", 3)
    row = _fresh(warehouse, "defectdojo")
    assert row["as_of"] == row["last_transform_success"]
    assert row["as_of"] < row["last_ingest_success"]
    assert row["never_succeeded"] == []
    assert row["age"] is not None
    assert row["targets"] == ["defectdojo_findings"]


def test_stale_raw_under_a_succeeding_transform_shows_the_ingest_time(
    warehouse: psycopg.Connection,
) -> None:
    """The V-18 case: a transform keeps reporting SUCCESS with 0 rows over raw
    that stopped arriving. The card must show the ingest's age, not the
    transform's."""
    _ingest(warehouse, "defectdojo", "SUCCESS", 30)
    _ingest(warehouse, "defectdojo", "FAILED", 1)
    _transform(warehouse, "defectdojo_findings", "SUCCESS", 0.1)
    row = _fresh(warehouse, "defectdojo")
    assert row["as_of"] == row["last_ingest_success"]
    assert row["age"].total_seconds() > 29 * 3600


def test_a_target_that_never_succeeded_makes_as_of_never_not_the_other_time(
    warehouse: psycopg.Connection,
) -> None:
    """least() would have returned the ingest time here."""
    _ingest(warehouse, "xsoar", "SUCCESS", 1)
    _transform(warehouse, "xsoar_incidents", "SUCCESS", 1)
    _transform(warehouse, "incident_lifecycle", "FAILED", 1)
    row = _fresh(warehouse, "xsoar")
    assert row["as_of"] is None
    assert row["age"] is None
    assert row["last_transform_success"] is None
    assert row["never_succeeded"] == ["incident_lifecycle"]


def test_an_ingest_that_never_succeeded_is_named(warehouse: psycopg.Connection) -> None:
    _ingest(warehouse, "wazuh", "FAILED", 1)
    _transform(warehouse, "wazuh_alerts", "SUCCESS", 1)
    row = _fresh(warehouse, "wazuh")
    assert row["as_of"] is None
    assert row["never_succeeded"] == ["ingest"]


def test_a_source_no_target_reads_is_as_fresh_as_its_ingest(
    warehouse: psycopg.Connection,
) -> None:
    _ingest(warehouse, "ksat_phishing_runs", "SUCCESS", 2)
    row = _fresh(warehouse, "ksat_phishing_runs")
    assert row["targets"] == []
    assert row["last_transform_success"] is None
    assert row["as_of"] == row["last_ingest_success"]


def test_a_source_the_mapping_does_not_know_still_gets_a_row(
    warehouse: psycopg.Connection,
) -> None:
    """A private connector the generating package could not see."""
    _ingest(warehouse, "phisher", "SUCCESS", 1)
    row = _fresh(warehouse, "phisher")
    assert (row["pack"], row["targets"], row["state"]) == (None, [], "ACTIVE")
    assert row["as_of"] == row["last_ingest_success"]


def test_held_out_shows_why_and_who(warehouse: psycopg.Connection) -> None:
    with login(warehouse, INGEST):
        warehouse.execute(HOLD, ("wazuh", "listed in ingest_disabled_sources"))
    row = _fresh(warehouse, "wazuh")
    assert row["state"] == "HELD_OUT"
    assert row["state_reason"] == "listed in ingest_disabled_sources"
    assert row["state_changed_by"] == INGEST
    assert row["state_changed_at"] is not None


def test_a_disabled_pack_shows_even_without_a_source_state_row(
    warehouse: psycopg.Connection,
) -> None:
    """A pack disabled before V-18 has a control.pack row and nothing else."""
    warehouse.execute(
        "INSERT INTO control.pack (name, version, state, disabled_at) "
        "VALUES ('builtin', '0.1.0', 'DISABLED', now())"
    )
    row = _fresh(warehouse, "defectdojo")
    assert row["state"] == "DISABLED"
    assert row["state_reason"] == "pack builtin is DISABLED in control.pack"
    assert row["state_changed_at"] is not None


def test_control_pack_overrides_a_stale_pack_row(warehouse: psycopg.Connection) -> None:
    """control.pack is what the worker obeys, so it decides when present."""
    warehouse.execute(
        "INSERT INTO control.source_state (source, origin, state, reason) "
        "VALUES ('defectdojo', 'pack', 'DISABLED', 'pack builtin disabled')"
    )
    warehouse.execute(
        "INSERT INTO control.pack (name, version, state, enabled_at) "
        "VALUES ('builtin', '0.1.0', 'ENABLED', now())"
    )
    assert _fresh(warehouse, "defectdojo")["state"] == "ACTIVE"


def test_reapplying_the_view_keeps_its_grants(warehouse: psycopg.Connection) -> None:
    warehouse.execute(source_freshness_sql(MAPPING))
    with login(warehouse, READ):
        assert _one(warehouse, "SELECT count(*) FROM control.source_freshness") == len(MAPPING)


# -- drift: dim, never dark ----------------------------------------------------------


@pytest.mark.parametrize("role", [INGEST, TRANSFORM, OTHER])
def test_drift_check_is_clean_under_each_worker(
    warehouse: psycopg.Connection, role: str
) -> None:
    with login(warehouse, role):
        assert schema_check.verify_control_schema(warehouse) == []


def test_a_warehouse_from_before_v18_runs_dim(
    warehouse: psycopg.Connection, caplog: pytest.LogCaptureFixture
) -> None:
    warehouse.execute("DROP VIEW control.source_freshness")
    warehouse.execute("DROP FUNCTION control.hold_out_source(text, text)")
    warehouse.execute("DROP FUNCTION control.release_source(text)")
    warehouse.execute("DROP TABLE control.source_state")
    with login(warehouse, INGEST):
        dim = schema_check.verify_control_schema(warehouse)
    assert dim == [
        "control.source_state does not exist",
        "control.source_freshness does not exist",
        "function control.hold_out_source(text, text) does not exist",
        "function control.release_source(text) does not exist",
    ]
    assert "running dim" in caplog.text


# -- the CLIs ---------------------------------------------------------------------


@pytest.fixture()
def dsn(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)
    return os.environ["SECOPS_TEST_DSN"]


def test_holdout_sync_records_then_clears(
    warehouse: psycopg.Connection, dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert holdout.main(["sync", "wazuh", "xsoar", "--reason", "listed"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "changed: true"
    assert _fresh(warehouse, "wazuh")["state"] == "HELD_OUT"

    assert holdout.main(["sync", "wazuh", "xsoar", "--reason", "listed"]) == 0
    assert capsys.readouterr().out.splitlines() == ["changed: false"]

    assert holdout.main(["sync", "xsoar", "--reason", "listed"]) == 0
    assert capsys.readouterr().out.splitlines() == ["released: wazuh", "changed: true"]
    assert _fresh(warehouse, "wazuh")["state"] == "ACTIVE"
    assert _fresh(warehouse, "xsoar")["state"] == "HELD_OUT"

    assert holdout.main(["list"]) == 0
    assert "xsoar  HELD_OUT  as of never (ingest,incident_lifecycle,xsoar_incidents)  listed" in (
        capsys.readouterr().out
    )


def test_holdout_sync_leaves_another_logins_hold_outs_alone(
    warehouse: psycopg.Connection, dsn: str
) -> None:
    with login(warehouse, OTHER):
        warehouse.execute(HOLD, ("wazuh", "enclave-01"))
    assert holdout.main(["sync", "--reason", "listed"]) == 0
    assert (_row(warehouse, "wazuh") or ())[3] == OTHER


def test_two_hosts_sharing_a_login_do_not_flap_with_managed(
    warehouse: psycopg.Connection, dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """ingest.yml holds xdr_alerts out; ingest-enclave.yml, same login, holds
    nothing. Each passes the sources it manages, so neither undoes the other."""
    warehouse_host = ["sync", "xdr_alerts", "--managed", "wazuh", "xdr", "xdr_alerts",
                      "--reason", "listed in ingest_disabled_sources"]
    enclave_host = ["sync", "--managed", "wazuh", "--reason", "listed in ingest_disabled_sources"]
    assert holdout.main(warehouse_host) == 0
    first = _row(warehouse, "xdr_alerts")
    capsys.readouterr()
    for _converge in range(2):
        assert holdout.main(enclave_host) == 0
        assert holdout.main(warehouse_host) == 0
    assert capsys.readouterr().out.splitlines() == ["changed: false"] * 4
    assert _row(warehouse, "xdr_alerts") == first


def test_holdout_against_a_warehouse_without_it_exits_dim(
    warehouse: psycopg.Connection, dsn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    warehouse.execute("DROP VIEW control.source_freshness")
    warehouse.execute("DROP TABLE control.source_state CASCADE")
    assert holdout.main(["sync", "wazuh", "--reason", "listed"]) == holdout.EXIT_DIM
    assert "running dim" in capsys.readouterr().err


def test_packs_disable_and_enable_mark_every_source(
    warehouse: psycopg.Connection, dsn: str
) -> None:
    assert packs_main(["disable", "builtin"]) == 0
    for source in BUILTIN.sources:
        state, reason, _at, _by = _row(warehouse, source, "pack") or ()
        assert (state, reason) == ("DISABLED", "pack builtin disabled"), source
    assert _fresh(warehouse, "defectdojo")["state_reason"] == "pack builtin disabled"
    first = _row(warehouse, "defectdojo", "pack")

    # Re-running keeps the moment it was first disabled.
    assert packs_main(["disable", "builtin"]) == 0
    assert _row(warehouse, "defectdojo", "pack") == first

    assert packs_main(["enable", "builtin", "--state-only"]) == 0
    state, reason, _at, _by = _row(warehouse, "defectdojo", "pack") or ()
    assert (state, reason) == ("ACTIVE", None)
    assert _fresh(warehouse, "defectdojo")["state"] == "ACTIVE"


def test_packs_enable_does_not_cancel_a_deployment_hold_out(
    warehouse: psycopg.Connection, dsn: str
) -> None:
    with login(warehouse, INGEST):
        warehouse.execute(HOLD, ("wazuh", "listed"))
    assert packs_main(["disable", "builtin"]) == 0
    assert packs_main(["enable", "builtin", "--state-only"]) == 0
    assert _fresh(warehouse, "wazuh")["state"] == "HELD_OUT"
