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
import time

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

from secops_ingest.packs import state as pack_state
from secops_ingest.schema import control_sql


class DatabaseLooksLive(RuntimeError):
    """The target database appears to hold real warehouse data.

    Test-only: this fixture drops `control` outright, and `control` is not a
    pack-only schema -- it also holds `ingest_run`, `transform_run` and,
    critically, `transform_coverage` (see the "THE COVERAGE LEDGER IS WHAT
    MAKES RAW EXPIRY SAFE" comment in schema/__init__.py). Destroying that
    ledger does not just lose rows here; it arms silent data loss against raw
    partition expiry across the whole warehouse. The realistic accident is
    someone pointing SECOPS_TEST_DSN at the value of SECOPS_DB_DSN.
    """


def _refuse_if_live(conn: psycopg.Connection) -> None:
    """Refuse to touch `conn`'s database if it looks like a real warehouse.

    Evidence-based, not name-based: a database name allowlist would not catch
    a production database that happens to be named something unexpected, and
    the failure mode we are guarding against is a pasted DSN, not a mistyped
    one. So this inspects actual content instead of the name, checking (in
    order of how strong the evidence is) for a populated coverage ledger, a
    populated run history, and any populated raw landing table.
    """
    with conn.cursor() as cur:
        for schema, table in (("control", "transform_coverage"), ("control", "ingest_run")):
            try:
                cur.execute(
                    psycopg.sql.SQL("SELECT count(*) FROM {}.{}").format(
                        psycopg.sql.Identifier(schema), psycopg.sql.Identifier(table)
                    )
                )
                row = cur.fetchone()
            except psycopg.errors.UndefinedTable:
                conn.rollback()
                continue
            count = row[0] if row is not None else 0
            if count:
                raise DatabaseLooksLive(
                    f"refusing to touch database {conn.info.dbname!r}: "
                    f"{schema}.{table} has {count} row(s). This looks like a real "
                    "warehouse, not a scratch test database -- the fixture will not "
                    "DROP SCHEMA control here. Check what SECOPS_TEST_DSN points at."
                )

        cur.execute(
            r"SELECT table_schema, table_name FROM information_schema.tables "
            r"WHERE table_schema LIKE 'raw\_%' ESCAPE '\'"
        )
        raw_tables = cur.fetchall()
        for schema, table in raw_tables:
            cur.execute(
                psycopg.sql.SQL("SELECT count(*) FROM {}.{}").format(
                    psycopg.sql.Identifier(schema), psycopg.sql.Identifier(table)
                )
            )
            row = cur.fetchone()
            count = row[0] if row is not None else 0
            if count:
                raise DatabaseLooksLive(
                    f"refusing to touch database {conn.info.dbname!r}: "
                    f"{schema}.{table} has {count} row(s). This looks like a real "
                    "warehouse, not a scratch test database -- the fixture will not "
                    "DROP SCHEMA control here. Check what SECOPS_TEST_DSN points at."
                )


@pytest.fixture()
def conn():  # type: ignore[no-untyped-def]
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"]) as c:
        _refuse_if_live(c)
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
    got = pack_state.get_state(conn, "builtin")
    assert got is not None
    enabled_at = got.enabled_at
    assert enabled_at is not None

    pack_state.set_state(conn, "builtin", "0.1.0", "DISABLED")
    got = pack_state.get_state(conn, "builtin")
    assert got is not None and got.state == "DISABLED"
    assert got.disabled_at is not None
    # Disabling must not clobber the earlier enable -- that history is the
    # whole point of these two columns rather than a single "state" flag.
    assert got.enabled_at == enabled_at


def test_re_enable_after_disable_restamps_enabled_at_and_keeps_disabled_at(
    conn,  # type: ignore[no-untyped-def]
) -> None:
    """The ON CONFLICT path is exactly where the other column could get clobbered.

    Walks enable -> disable -> enable and checks both timestamps by value at
    each step, not just for non-nullness: disabling must not touch enabled_at,
    re-enabling must not touch disabled_at, and the re-enable must actually
    restamp enabled_at to a new value rather than silently carrying the first
    one forward.
    """
    pack_state.apply_ddl(conn, control_sql())

    pack_state.set_state(conn, "builtin", "0.1.0", "ENABLED")
    first = pack_state.get_state(conn, "builtin")
    assert first is not None
    assert first.enabled_at is not None
    assert first.disabled_at is None

    time.sleep(0.01)  # guarantee now() advances between statements
    pack_state.set_state(conn, "builtin", "0.1.0", "DISABLED")
    disabled = pack_state.get_state(conn, "builtin")
    assert disabled is not None
    assert disabled.disabled_at is not None
    assert disabled.enabled_at == first.enabled_at  # untouched by the disable

    time.sleep(0.01)
    pack_state.set_state(conn, "builtin", "0.1.0", "ENABLED")
    reenabled = pack_state.get_state(conn, "builtin")
    assert reenabled is not None
    assert reenabled.disabled_at == disabled.disabled_at  # untouched by the re-enable
    assert reenabled.enabled_at is not None
    assert reenabled.enabled_at != first.enabled_at  # restamped, not carried forward


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


def test_the_guard_refuses_a_database_holding_real_ingest_history() -> None:
    """Prove the guard itself, against the live database.

    Deliberately does not use the `conn` fixture: the fixture's own guard
    would fire during setup, before this test gets a chance to plant the row
    that is supposed to trip it. Everything this test creates is torn down
    at the end, so it does not leave `control.ingest_run` populated for the
    six tests around it -- which would otherwise poison every one of them via
    the same guard.
    """
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"]) as c:
        c.execute("DROP SCHEMA IF EXISTS control CASCADE")
        c.commit()
        try:
            c.execute(control_sql())
            c.commit()
            c.execute(
                "INSERT INTO control.ingest_run (source, status) VALUES ('probe', 'SUCCESS')"
            )
            c.commit()

            with pytest.raises(DatabaseLooksLive, match="ingest_run"):
                _refuse_if_live(c)
        finally:
            c.execute("DROP SCHEMA IF EXISTS control CASCADE")
            c.commit()


def test_enable_then_disable_round_trip(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    assert pack_state.get_state(conn, "builtin").state == "ENABLED"  # type: ignore[union-attr]
    assert main(["disable", "builtin"]) == 0
    assert pack_state.get_state(conn, "builtin").state == "DISABLED"  # type: ignore[union-attr]


def test_enable_creates_the_packs_tables(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    got = conn.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema LIKE 'raw_%'"
    ).fetchone()[0]
    assert got > 0


def test_enable_twice_is_idempotent(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    assert main(["enable", "builtin"]) == 0


def test_disable_without_a_prior_enable_succeeds(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Disabling something that was never enabled must not fail a converge.

    An Ansible run that flips a pack off has to be idempotent whether or not
    it was ever on -- `builtin` here has no row at all, since `control` was
    just dropped by the fixture and no enable has run.

    What this implementation actually does: it writes a DISABLED row rather
    than leaving no row behind. That is deliberate, not incidental -- a
    stored DISABLED row lets a later `control.pack` query tell "known to
    this install, and off" apart from "never seen here at all", which no row
    cannot do. Writing it costs nothing extra: control_sql() only touches
    `control.*`, so this is still "the row and nothing else" -- in
    particular, no raw_* schema gets created by it, which the assertion below
    pins by count rather than by absolute zero: earlier tests in this module
    may have already left raw_* schemas behind (the `conn` fixture only drops
    `control`, on purpose -- see its docstring), so this compares the count
    before and after rather than assuming a pristine database.
    """
    from secops_ingest.packs.__main__ import main

    raw_tables_before = conn.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema LIKE 'raw_%'"
    ).fetchone()[0]

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["disable", "builtin"]) == 0

    got = pack_state.get_state(conn, "builtin")
    assert got is not None
    assert got.state == "DISABLED"

    raw_tables_after = conn.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema LIKE 'raw_%'"
    ).fetchone()[0]
    assert raw_tables_after == raw_tables_before
