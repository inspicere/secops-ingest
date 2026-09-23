"""enable/disable argument handling and failure paths, without a database."""

from __future__ import annotations

import pytest

from secops_ingest.packs.__main__ import main


def test_enable_requires_a_pack_name(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["enable"])


def test_enable_without_a_dsn_names_the_variable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    assert main(["enable", "builtin"]) == 1
    assert "SECOPS_DB_DSN" in capsys.readouterr().err


def test_enable_unknown_pack_names_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")
    assert main(["enable", "nosuchpack"]) == 1
    err = capsys.readouterr().err
    assert "nosuchpack" in err


def test_enable_labels_a_connection_failure_as_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Minor finding: `enable` must separate a connect failure from an
    operate failure, the same distinction `list` already makes."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(dsn: str) -> None:
        raise psycopg.OperationalError("could not translate host name")

    monkeypatch.setattr(psycopg, "connect", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unreachable/db")

    assert main(["enable", "builtin"]) == 1
    err = capsys.readouterr().err
    assert "could not connect" in err.lower()
    assert "could not enable" not in err.lower()


def test_enable_labels_a_ddl_failure_as_an_enable_problem_not_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other half: a reachable database that then fails the DDL/upsert
    must not be reported as though the DSN itself were the problem."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    class _FakeConnection:
        def close(self) -> None:
            return None

    def _boom(*args: object, **kwargs: object) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for schema control")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.apply_ddl", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["enable", "builtin"]) == 1
    err = capsys.readouterr().err
    assert "connected, but could not enable" in err.lower()
    assert "could not connect" not in err.lower()


def test_disable_labels_a_connection_failure_as_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(dsn: str) -> None:
        raise psycopg.OperationalError("could not translate host name")

    monkeypatch.setattr(psycopg, "connect", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unreachable/db")

    assert main(["disable", "builtin"]) == 1
    err = capsys.readouterr().err
    assert "could not connect" in err.lower()
    assert "could not disable" not in err.lower()


def test_disable_labels_a_ddl_failure_as_a_disable_problem_not_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    class _FakeConnection:
        def close(self) -> None:
            return None

    def _boom(*args: object, **kwargs: object) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for schema control")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.apply_ddl", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["disable", "builtin"]) == 1
    err = capsys.readouterr().err
    assert "connected, but could not disable" in err.lower()
    assert "could not connect" not in err.lower()


def test_list_still_works_with_no_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The property Task 3 must not take away: the diagnostic command works on
    # a machine with no driver and no database.
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    assert main(["list"]) == 0
    assert "builtin" in capsys.readouterr().out


def test_enable_named_pack_exists_but_incompatible_core_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """"unknown pack" would blame the wrong thing here.

    discover() itself drops an incompatible pack silently -- by design, so one
    pack's version skew cannot take every other pack's listing down with it --
    so `enable` has to look past discover() to tell "never existed" apart from
    "exists, but this install's core is too old for it".
    """
    from secops_ingest.packs.model import Pack

    class _FakeEntryPoint:
        name = "toonew"
        dist = type("Dist", (), {"name": "test-dist"})()

        def load(self) -> Pack:
            return Pack(
                name="toonew",
                version="9.0.0",
                requires_core=">=9,<10",
                sources={"thing": "toonew.thing:SOURCE"},
            )

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.entry_points",
        lambda group: [_FakeEntryPoint()],
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["enable", "toonew"]) == 1
    err = capsys.readouterr().err
    assert "toonew" in err
    assert "core" in err


def test_enable_target_not_schema_qualified_reports_pack_and_target(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ddl_for_targets() raises for a target it never had to see at emitter time.

    schema/__main__.py pre-checks raw_table for every real target, so this
    ValueError never surfaces there -- but a third-party pack can ship a
    target that skips that check entirely, and `enable` is the first thing
    that actually calls ddl_for_targets() against it. Injected the same way
    tests/packs/test_registry.py injects a fake entry point: no real database
    is ever touched, because ddl_for_targets() raises before any connection
    is opened.
    """
    from secops_ingest.packs.model import Pack
    from secops_ingest.packs.registry import discover
    from secops_ingest.transform.base import Target

    bad_target = Target(
        name="bad_target",
        raw_table="not_schema_qualified",
        fact_table="mart_fact_bad_target",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_bad_target SELECT %(since)s::timestamptz",
    )
    bad_pack = Pack(
        name="badpack",
        version="0.1.0",
        requires_core=">=0",
        sources={"thing": "badpack.thing:SOURCE"},
        targets=(bad_target,),
    )

    class _FakeEntryPoint:
        name = "badpack"
        dist = type("Dist", (), {"name": "test-dist"})()

        def load(self) -> Pack:
            return bad_pack

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover",
        lambda: discover(extra=[_FakeEntryPoint()]),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["enable", "badpack"]) == 1
    err = capsys.readouterr().err
    assert "badpack" in err
    assert "bad_target" in err


class _ZeroRowCursor:
    """Enough of a psycopg cursor for `drop`'s row-count queries to read 0."""

    def __enter__(self) -> _ZeroRowCursor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, *args: object, **kwargs: object) -> None:
        return None

    def fetchone(self) -> tuple[int]:
        return (0,)


class _FakeDropConnection:
    """Enough of a psycopg connection for `drop` to run its own logic against,
    with nothing actually stored anywhere."""

    def cursor(self) -> _ZeroRowCursor:
        return _ZeroRowCursor()

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


def _stub_disabled_state(monkeypatch: pytest.MonkeyPatch, psycopg: object) -> None:
    from secops_ingest.packs.state import PackState

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeDropConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.get_state",
        lambda conn, name: PackState(
            name=name, version="0.1.0", state="DISABLED", enabled_at=None, disabled_at=None
        ),
    )


def test_drop_without_the_flag_refuses_with_precise_wording(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F3: a refusal and a destruction must not print byte-identical stdout.

    Replaces the old hedged assertion ("DROP not in out or 'would' in out"),
    which could not actually tell the two apart. No real database: `drop`
    requires the pack to be DISABLED first (F4), so both `psycopg.connect`
    and `state.get_state` are stubbed to report exactly that, with every
    table reading 0 rows, and the test asserts the refusal's exact wording.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    _stub_disabled_state(monkeypatch, psycopg)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin"]) == 1
    out = capsys.readouterr().out
    assert "would destroy the data for pack 'builtin':" in out
    assert "destroying the data for pack 'builtin':" not in out
    assert "refusing: pass --yes-destroy-data to actually destroy this data." in out


def test_drop_with_the_flag_says_destroying_and_destroyed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other half of F3: the destroy path's header and closing line must
    read differently from the refusal's, not just differ by exit code."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    _stub_disabled_state(monkeypatch, psycopg)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 0
    out = capsys.readouterr().out
    assert "destroying the data for pack 'builtin':" in out
    assert "would destroy the data for pack 'builtin':" not in out
    assert "destroyed the data for pack 'builtin'." in out
    assert "refusing" not in out


def test_drop_of_an_enabled_pack_refuses_and_says_disable_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F4: a still-ENABLED pack must not be dropped -- its timer could still
    fire, or a run could already be in flight."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest.packs.state import PackState

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeDropConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.get_state",
        lambda conn, name: PackState(
            name=name, version="0.1.0", state="ENABLED", enabled_at=None, disabled_at=None
        ),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "builtin" in err
    assert "is ENABLED" in err
    assert "disable builtin" in err


def test_drop_with_no_recorded_state_refuses(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F4's other half: no row at all is exactly the shape
    `run._pack_state_of` treats as PROCEED, so it must refuse too."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeDropConnection())
    monkeypatch.setattr("secops_ingest.packs.state.get_state", lambda conn, name: None)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "builtin" in err
    assert "has no recorded state" in err
    assert "disable builtin" in err


def test_drop_labels_a_connection_failure_as_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Minor finding: `drop` must separate a connect failure from an operate
    failure too, the same distinction `list` already makes."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(dsn: str) -> None:
        raise psycopg.OperationalError("could not translate host name")

    monkeypatch.setattr(psycopg, "connect", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unreachable/db")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "could not connect" in err.lower()
    assert "could not drop" not in err.lower()


def test_drop_labels_a_query_failure_as_a_drop_problem_not_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other half: a reachable database that then fails a query must not
    be reported as though the DSN itself were the problem."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(conn: object, name: str) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for table pack")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeDropConnection())
    monkeypatch.setattr("secops_ingest.packs.state.get_state", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "connected, but could not drop" in err.lower()
    assert "could not connect" not in err.lower()


def _source_colliding_pack() -> object:
    from secops_ingest.packs.model import Pack

    return Pack(
        name="shadow",
        version="0.1.0",
        requires_core=">=0",
        # Collides with builtin's own "example" source -- legal at enable
        # time, but not something `drop` can safely attribute.
        sources={"example": "shadow.example:SOURCE"},
    )


def test_drop_refuses_on_a_source_name_collision_and_destroys_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F1: `drop` must not delete another pack's ingest bookkeeping.

    Two packs may legally share a bare source name -- `resolve_source`
    disambiguates an operator's qualified reference, and `enable` never
    refuses this -- but `control.ingest_run.source` and
    `control.ingest_watermark.source` store only the bare name, so `drop`'s
    `WHERE source = ANY(...)` cannot tell whose rows they are.
    `psycopg.connect` is stubbed to raise if ever called, proving the refusal
    happens before any connection opens -- same property as the target-name
    collision test below.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest.packs.registry import discover

    class _FakeEntryPoint:
        name = "shadow"
        dist = type("Dist", (), {"name": "shadow-dist"})()

        def load(self) -> object:
            return _source_colliding_pack()

    def _must_not_connect(dsn: str) -> None:
        raise AssertionError("drop must refuse before opening a connection")

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover",
        lambda: discover(extra=[_FakeEntryPoint()]),
    )
    monkeypatch.setattr(psycopg, "connect", _must_not_connect)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "example" in err
    assert "builtin" in err
    assert "shadow" in err


class _RecordingCursor:
    """Records what SQL it was asked to run, in order; every query reads 0 rows."""

    def __init__(self, log: list[str]) -> None:
        self._log = log

    def __enter__(self) -> _RecordingCursor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, query: object, *args: object, **kwargs: object) -> None:
        text = str(query)
        if "DROP TABLE" in text:
            self._log.append("DROP TABLE")
        elif "DELETE FROM" in text:
            self._log.append("DELETE")
        else:
            self._log.append("OTHER")  # e.g. the row-count SELECTs

    def fetchone(self) -> tuple[int]:
        return (0,)


class _RecordingConnection:
    def __init__(self) -> None:
        self.log: list[str] = []

    def cursor(self) -> _RecordingCursor:
        return _RecordingCursor(self.log)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


def test_drop_deletes_bookkeeping_before_dropping_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F2: bookkeeping must be deleted BEFORE tables are dropped -- the
    inverse of `enable`'s "the control row is written strictly last" rule.

    A crash between the two steps then leaves tables with no bookkeeping
    (recoverable: re-running `drop`, or `enable`, finishes the job) rather
    than bookkeeping with no tables (permanent: raw is a bounded
    re-derivation buffer, ADR-0002, so a resumed worker trusts the stale
    watermark and never re-fetches the gap). No real database: every SQL
    statement `drop` issues is recorded, in order, by a fake cursor.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest.packs.state import PackState

    conn = _RecordingConnection()
    monkeypatch.setattr(psycopg, "connect", lambda dsn: conn)
    monkeypatch.setattr(
        "secops_ingest.packs.state.get_state",
        lambda c, name: PackState(
            name=name, version="0.1.0", state="DISABLED", enabled_at=None, disabled_at=None
        ),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 0

    delete_indices = [i for i, op in enumerate(conn.log) if op == "DELETE"]
    drop_indices = [i for i, op in enumerate(conn.log) if op == "DROP TABLE"]
    assert delete_indices, "expected at least one bookkeeping DELETE"
    assert drop_indices, "expected at least one DROP TABLE"
    assert max(delete_indices) < min(drop_indices)


def test_drop_unknown_pack_names_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")
    assert main(["drop", "nosuchpack", "--yes-destroy-data"]) == 1
    assert "nosuchpack" in capsys.readouterr().err


def _colliding_pack() -> object:
    from secops_ingest.packs.model import Pack
    from secops_ingest.transform.base import Target

    colliding = Target(
        name="example_messages",  # collides with builtin's own target name
        raw_table="raw_evil.messages",
        fact_table="mart_fact_evil_messages",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_evil_messages SELECT %(since)s::timestamptz",
    )
    return Pack(
        name="evil",
        version="0.1.0",
        requires_core=">=0",
        sources={"thing": "evil.thing:SOURCE"},
        targets=(colliding,),
    )


def test_enable_refuses_on_a_target_name_collision(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """all_targets() must be checked on enable's path too, not just list's.

    A pack declaring a target name that collides with an already-installed
    pack's target must stop `enable` cold -- on EITHER pack's name -- before
    any DDL is generated or applied, because that DDL and drop's later
    deletes are both keyed by target name.
    """
    from secops_ingest.packs.registry import discover

    class _FakeEntryPoint:
        name = "evil"
        dist = type("Dist", (), {"name": "evil-dist"})()

        def load(self) -> object:
            return _colliding_pack()

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover",
        lambda: discover(extra=[_FakeEntryPoint()]),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["enable", "builtin"]) == 1
    err = capsys.readouterr().err
    assert "example_messages" in err
    assert "builtin" in err
    assert "evil" in err

    assert main(["enable", "evil"]) == 1
    err = capsys.readouterr().err
    assert "example_messages" in err
    assert "builtin" in err
    assert "evil" in err


def test_drop_refuses_on_a_target_name_collision_and_destroys_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The property that matters for a destructive verb: not just exit 1.

    `drop`'s control-row deletes are scoped `WHERE target = ANY(...)` by
    name, which is only safe if target names are unique across every
    installed pack. `psycopg.connect` is stubbed to raise if it is ever
    called at all, so this proves the collision is caught before any
    connection opens -- nothing gets a chance to be destroyed, not merely
    that the command happens to exit non-zero.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest.packs.registry import discover

    class _FakeEntryPoint:
        name = "evil"
        dist = type("Dist", (), {"name": "evil-dist"})()

        def load(self) -> object:
            return _colliding_pack()

    def _must_not_connect(dsn: str) -> None:
        raise AssertionError("drop must refuse before opening a connection")

    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover",
        lambda: discover(extra=[_FakeEntryPoint()]),
    )
    monkeypatch.setattr(psycopg, "connect", _must_not_connect)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["drop", "builtin", "--yes-destroy-data"]) == 1
    err = capsys.readouterr().err
    assert "example_messages" in err
    assert "builtin" in err
    assert "evil" in err


def test_disable_unregistered_with_no_row_names_the_pack(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`disable nosuchpack` must fail naming the pack, not just exit non-zero.

    Unlike `enable`, `disable`'s failure decision for an unregistered pack
    depends on whether the warehouse has a row for it (a pack that was
    uninstalled but once ran here should still disable cleanly), so it
    genuinely has to connect before it can tell "never existed" apart from
    "known, no row". The DSN is deliberately unusable, as the other tests in
    this file use, but `psycopg.connect` and `state.get_state` are stubbed so
    the connection "succeeds" and reports no row -- proving this exit 1 comes
    from the pack being unknown, not from the fake DSN failing to resolve.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    class _FakeConnection:
        def close(self) -> None:
            return None

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.get_state", lambda conn, name: None)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["disable", "nosuchpack"]) == 1
    err = capsys.readouterr().err
    assert "nosuchpack" in err
