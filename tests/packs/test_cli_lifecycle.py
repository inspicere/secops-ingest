"""enable/disable argument handling and failure paths, without a database."""

from __future__ import annotations

from typing import Self

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


def test_drop_without_the_flag_refuses_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A refusal, not a report: a script that ignores the exit code must not
    # then proceed as though the data were gone.
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")
    assert main(["drop", "builtin"]) != 0
    out = capsys.readouterr()
    assert "DROP" not in out.out.upper() or "would" in out.out.lower()


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
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc_info: object) -> None:
            return None

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.get_state", lambda conn, name: None)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unused")

    assert main(["disable", "nosuchpack"]) == 1
    err = capsys.readouterr().err
    assert "nosuchpack" in err
