"""Pack state against a real PostgreSQL.

Skipped unless SECOPS_TEST_DSN is set, so `pytest` on a laptop with no server
still passes and the suite keeps its no-database guarantee by default. This
mirrors tests/secrets/test_vault_backend_integration.py, which does the same
for a real Vault-API server.

    docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=secops \
        postgres:16
    SECOPS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:5433/secops \
        pytest tests/packs/test_state_integration.py -v
"""

from __future__ import annotations

import os

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

from secops_ingest.packs import state as pack_state
from secops_ingest.schema import control_sql


@pytest.fixture()
def conn():  # type: ignore[no-untyped-def]
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"]) as c:
        c.execute("DROP SCHEMA IF EXISTS control CASCADE")
        c.commit()
        yield c


def test_missing_table_reads_as_no_state_not_an_error(conn) -> None:  # type: ignore[no-untyped-def]
    # A warehouse provisioned before this change has no control.pack. Raising
    # here would turn an upgrade into an outage the first time a worker ran.
    assert pack_state.get_state(conn, "builtin") is None
    assert pack_state.all_states(conn) == {}


def test_round_trip(conn) -> None:  # type: ignore[no-untyped-def]
    pack_state.apply_ddl(conn, control_sql())
    pack_state.set_state(conn, "builtin", "0.1.0", "ENABLED")
    got = pack_state.get_state(conn, "builtin")
    assert got is not None
    assert (got.name, got.version, got.state) == ("builtin", "0.1.0", "ENABLED")
    assert got.enabled_at is not None
    assert got.disabled_at is None


def test_disable_sets_the_timestamp_and_keeps_the_row(conn) -> None:  # type: ignore[no-untyped-def]
    pack_state.apply_ddl(conn, control_sql())
    pack_state.set_state(conn, "builtin", "0.1.0", "ENABLED")
    pack_state.set_state(conn, "builtin", "0.1.0", "DISABLED")
    got = pack_state.get_state(conn, "builtin")
    assert got is not None and got.state == "DISABLED"
    assert got.disabled_at is not None


def test_re_enabling_is_idempotent(conn) -> None:  # type: ignore[no-untyped-def]
    pack_state.apply_ddl(conn, control_sql())
    for _ in range(3):
        pack_state.set_state(conn, "builtin", "0.1.0", "ENABLED")
    assert pack_state.all_states(conn)["builtin"].state == "ENABLED"


def test_applying_control_ddl_twice_is_safe(conn) -> None:  # type: ignore[no-untyped-def]
    pack_state.apply_ddl(conn, control_sql())
    pack_state.apply_ddl(conn, control_sql())
    assert pack_state.all_states(conn) == {}


def test_the_check_constraint_is_real(conn) -> None:  # type: ignore[no-untyped-def]
    pack_state.apply_ddl(conn, control_sql())
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO control.pack (name, version, state) VALUES ('x','1','off')"
        )
