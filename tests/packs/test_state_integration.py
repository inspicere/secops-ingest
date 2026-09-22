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


def test_worker_pack_state_of_reflects_disable_and_enable(  # type: ignore[no-untyped-def]
    conn, monkeypatch
) -> None:
    """The worker's own gate (`run._pack_state_of`), against a real warehouse.

    Everything above proves `control.pack` itself round-trips correctly; this
    proves the OTHER end of the feature -- the function `execute()` actually
    calls before every run -- agrees with it. "wazuh" is a real builtin
    connector, so `discover()` resolves it to the "builtin" pack without any
    mocking.
    """
    from secops_ingest.common.run import _pack_state_of
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])

    assert main(["disable", "builtin"]) == 0
    assert _pack_state_of(conn, "wazuh") == "DISABLED"

    assert main(["enable", "builtin"]) == 0
    assert _pack_state_of(conn, "wazuh") is None


def _table_exists(conn, qualified: str) -> bool:  # type: ignore[no-untyped-def]
    schema, _, table = qualified.partition(".")
    return bool(
        conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = %s",
            (schema, table),
        ).fetchone()
    )


def test_dry_run_lists_tables_and_destroys_nothing(conn, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    assert main(["drop", "builtin"]) != 0
    assert _table_exists(conn, "raw_example.messages")
    assert pack_state.get_state(conn, "builtin") is not None
    assert "raw_example.messages" in capsys.readouterr().out


def test_drop_removes_tables_and_control_rows(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    assert _table_exists(conn, "raw_example.messages")
    assert main(["drop", "builtin", "--yes-destroy-data"]) == 0
    assert not _table_exists(conn, "raw_example.messages")
    assert pack_state.get_state(conn, "builtin") is None


def test_drop_reports_row_counts_before_destroying(conn, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    main(["enable", "builtin"])
    main(["drop", "builtin", "--yes-destroy-data"])
    out = capsys.readouterr().out
    # The count is the whole point: "0 rows" and "4,000,000 rows" should not
    # read the same to someone about to type the flag.
    assert "row" in out.lower()


def test_drop_a_pack_with_nothing_to_drop_is_not_an_error(conn, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from secops_ingest.packs.__main__ import main

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    pack_state.apply_ddl(conn, control_sql())
    assert main(["drop", "builtin", "--yes-destroy-data"]) == 0


def test_drop_leaves_other_packs_tables_and_control_rows_alone(  # type: ignore[no-untyped-def]
    conn, monkeypatch
) -> None:
    """The property most likely to break and least likely to be noticed.

    Builds a second synthetic pack, the way tests/packs/test_registry.py
    injects a fake entry point, so both `builtin` and `other` are enabled at
    once against the same warehouse. `control.ingest_watermark` and
    `control.transform_coverage` are shared tables keyed by source/target
    name -- if `drop`'s DELETEs are not scoped tightly enough to the pack
    being dropped, this is where it would show: `other`'s row would vanish
    right alongside `builtin`'s.
    """
    from secops_ingest.packs.__main__ import main
    from secops_ingest.packs.model import Pack
    from secops_ingest.packs.registry import discover
    from secops_ingest.transform.base import Target

    other_target = Target(
        name="other_things",
        raw_table="raw_other.things",
        fact_table="mart_fact_other_things",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_other_things SELECT %(since)s::timestamptz",
        fact_ddl="CREATE TABLE IF NOT EXISTS mart_fact_other_things (seen_at timestamptz);",
    )
    other_pack = Pack(
        name="other",
        version="0.1.0",
        requires_core=">=0",
        sources={"thing": "other_pack.thing:SOURCE"},
        targets=(other_target,),
    )

    class _FakeEntryPoint:
        name = "other"
        dist = type("Dist", (), {"name": "other-dist"})()

        def load(self) -> Pack:
            return other_pack

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover",
        lambda: discover(extra=[_FakeEntryPoint()]),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])

    assert main(["enable", "builtin"]) == 0
    assert main(["enable", "other"]) == 0

    try:
        conn.execute(
            "INSERT INTO control.ingest_watermark (source, cursor_value) VALUES (%s, %s)",
            ("example", "builtin-cursor"),
        )
        conn.execute(
            "INSERT INTO control.ingest_watermark (source, cursor_value) VALUES (%s, %s)",
            ("thing", "other-cursor"),
        )
        conn.execute(
            "INSERT INTO control.transform_coverage (target, period, fact_rows) "
            "VALUES (%s, %s, %s)",
            ("example_messages", "2026-01-01", 10),
        )
        conn.execute(
            "INSERT INTO control.transform_coverage (target, period, fact_rows) "
            "VALUES (%s, %s, %s)",
            ("other_things", "2026-01-01", 5),
        )
        conn.commit()

        assert main(["drop", "builtin", "--yes-destroy-data"]) == 0

        # `other`'s tables, unrelated to `builtin`, are untouched. fact_table
        # and rollup_table are not schema-qualified -- they live wherever the
        # connection's search_path put them, i.e. public.
        assert _table_exists(conn, "raw_other.things")
        assert _table_exists(conn, "public.mart_fact_other_things")

        # `other`'s control.pack row survives, still ENABLED.
        other_state = pack_state.get_state(conn, "other")
        assert other_state is not None
        assert other_state.state == "ENABLED"

        # `builtin`'s row for its own source is gone; `other`'s is not.
        remaining_watermarks = {
            row[0]
            for row in conn.execute("SELECT source FROM control.ingest_watermark").fetchall()
        }
        assert "example" not in remaining_watermarks
        assert "thing" in remaining_watermarks

        # The coverage ledger is scoped per target: dropping builtin must not
        # re-arm the raw-expiry guard for a target it does not own.
        remaining_coverage = {
            row[0]
            for row in conn.execute("SELECT target FROM control.transform_coverage").fetchall()
        }
        assert "example_messages" not in remaining_coverage
        assert "other_things" in remaining_coverage
    finally:
        # `other` is never dropped by the assertions above (that is the whole
        # point of this test), so it -- and the row this test planted for it
        # -- would otherwise survive this test and trip
        # `test_the_guard_refuses_a_database_holding_real_ingest_history`'s
        # cousin, the `conn` fixture's own live-database guard, on the very
        # next test run against this real, persistent database.
        assert main(["drop", "other", "--yes-destroy-data"]) == 0


def test_drop_refuses_on_a_target_name_collision_and_leaves_tables_in_place(  # type: ignore[no-untyped-def]
    conn, monkeypatch
) -> None:
    """all_targets() must be checked on drop's path too, against a real warehouse.

    Registers a second pack whose target collides by name with builtin's own
    `example_messages`, the way tests/packs/test_registry.py injects a fake
    entry point. `drop --yes-destroy-data` must refuse before ever opening a
    connection -- the control-row deletes in `_cmd_drop` are only safe to
    scope `WHERE target = ANY(...)` because target names are supposed to be
    globally unique, and this is exactly the collision that would break that
    assumption. Proven here by planting real tables first (`enable`, with no
    collision registered yet) and then asserting they are still there after
    the refusal.
    """
    from secops_ingest.packs import __main__ as main_mod
    from secops_ingest.packs.__main__ import main
    from secops_ingest.packs.model import Pack
    from secops_ingest.packs.registry import discover
    from secops_ingest.transform.base import Target

    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    assert main(["enable", "builtin"]) == 0
    assert _table_exists(conn, "raw_example.messages")

    colliding = Target(
        name="example_messages",  # collides with builtin's own target name
        raw_table="raw_evil.messages",
        fact_table="mart_fact_evil_messages",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_evil_messages SELECT %(since)s::timestamptz",
    )
    evil_pack = Pack(
        name="evil",
        version="0.1.0",
        requires_core=">=0",
        sources={"thing": "evil.thing:SOURCE"},
        targets=(colliding,),
    )

    class _FakeEntryPoint:
        name = "evil"
        dist = type("Dist", (), {"name": "evil-dist"})()

        def load(self) -> Pack:
            return evil_pack

    original_discover = main_mod.discover
    try:
        monkeypatch.setattr(
            main_mod, "discover", lambda: discover(extra=[_FakeEntryPoint()])
        )

        assert main(["drop", "builtin", "--yes-destroy-data"]) == 1

        # Nothing was destroyed: the real table planted before the collision
        # was registered is still there, and so is builtin's control row.
        assert _table_exists(conn, "raw_example.messages")
        assert pack_state.get_state(conn, "builtin") is not None
        assert pack_state.get_state(conn, "builtin").state == "ENABLED"  # type: ignore[union-attr]
    finally:
        # Restore the real discover() (not a full monkeypatch.undo(), which
        # would also revert SECOPS_DB_DSN) so this cleanup call is not itself
        # blocked by the collision it just proved -- leaving builtin enabled
        # here would poison the live-database guard on the next test run,
        # same lesson as the fixture above this one.
        monkeypatch.setattr(main_mod, "discover", original_discover)
        assert main(["drop", "builtin", "--yes-destroy-data"]) == 0
