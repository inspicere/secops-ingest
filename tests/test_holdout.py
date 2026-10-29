"""`python -m secops_ingest.holdout`, without a database.

What the converge relies on: argument checks before any connection, the exit
code that separates "warehouse too old, running dim" (3) from a failure (1),
and the `changed:` line. tests/schema/test_source_state_integration.py runs
the same commands against PostgreSQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest import holdout  # noqa: E402


class _Cursor:
    def __init__(self, exc: Exception | None, rows: list[tuple[Any, ...]]) -> None:
        self._exc = exc
        self._rows = rows

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> None:
        if self._exc is not None:
            raise self._exc

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _Conn:
    def __init__(self, exc: Exception | None = None, rows: list[tuple[Any, ...]] | None = None):
        self._exc = exc
        self._rows = rows or []
        self.rollbacks = 0

    def cursor(self) -> _Cursor:
        return _Cursor(self._exc, self._rows)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        self.rollbacks += 1


def _use(monkeypatch: pytest.MonkeyPatch, conn: _Conn) -> None:
    @contextmanager
    def fake() -> Iterator[_Conn]:
        yield conn

    monkeypatch.setattr(holdout, "_connect", fake)


@pytest.mark.parametrize("command", ["sync", "hold"])
def test_a_hold_out_needs_a_reason(command: str) -> None:
    with pytest.raises(SystemExit):
        holdout.main([command, "xdr_alerts"])


def test_a_blank_reason_is_refused_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(holdout, "_connect", lambda: pytest.fail("connected"))
    with pytest.raises(SystemExit):
        holdout.main(["hold", "xdr_alerts", "--reason", "   "])


def test_a_name_that_is_not_an_identifier_is_refused_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(holdout, "_connect", lambda: pytest.fail("connected"))
    with pytest.raises(SystemExit):
        holdout.main(["hold", "x'; drop", "--reason", "r"])


def test_no_dsn_is_one_line_and_exit_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)
    assert holdout.main(["sync", "--reason", "r"]) == 1
    assert "SECOPS_DB_DSN is not set" in capsys.readouterr().err


@pytest.mark.parametrize(
    "exc",
    [
        psycopg.errors.UndefinedTable('relation "control.source_state" does not exist'),
        psycopg.errors.UndefinedFunction("function control.hold_out_source does not exist"),
    ],
)
def test_a_warehouse_without_the_objects_is_dim_exit_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], exc: Exception
) -> None:
    conn = _Conn(exc)
    _use(monkeypatch, conn)
    assert holdout.main(["hold", "xdr_alerts", "--reason", "r"]) == holdout.EXIT_DIM
    err = capsys.readouterr().err
    assert err.startswith("running dim:")
    assert "nothing was recorded" in err
    assert "schema owner" in err
    assert conn.rollbacks == 1


def test_a_refused_release_is_a_failure_not_dim(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use(monkeypatch, _Conn(psycopg.errors.InsufficientPrivilege(
        "source ksat is held out by wh_ingest, not by other")))
    assert holdout.main(["release", "ksat"]) == 1
    assert "held out by wh_ingest" in capsys.readouterr().err


def test_sync_holds_the_list_and_releases_only_the_rest_of_mine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use(monkeypatch, _Conn())
    held: list[str] = []
    released: list[str] = []
    monkeypatch.setattr(holdout, "hold", lambda c, s, r: held.append(s) or s == "ksat")
    monkeypatch.setattr(holdout, "my_hold_outs", lambda c: ["ksat", "wazuh", "xdr_alerts"])
    monkeypatch.setattr(holdout, "release", lambda c, s: released.append(s) or True)

    assert holdout.main(["sync", "xdr_alerts", "ksat", "--reason", "listed"]) == 0

    assert held == ["xdr_alerts", "ksat"]
    assert released == ["wazuh"]
    out = capsys.readouterr().out.splitlines()
    assert out == ["held out: ksat (listed)", "released: wazuh", "changed: true"]


def test_sync_with_nothing_to_do_says_changed_false(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use(monkeypatch, _Conn())
    monkeypatch.setattr(holdout, "hold", lambda c, s, r: False)
    monkeypatch.setattr(holdout, "my_hold_outs", lambda c: ["xdr_alerts"])
    monkeypatch.setattr(holdout, "release", lambda c, s: pytest.fail("released"))
    assert holdout.main(["sync", "xdr_alerts", "--reason", "listed"]) == 0
    assert capsys.readouterr().out.splitlines() == ["changed: false"]


def test_an_undeclared_source_is_warned_about_and_still_recorded(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use(monkeypatch, _Conn(rows=[(True,)]))
    assert holdout.main(["hold", "xdr_alertz", "--reason", "typo"]) == 0
    captured = capsys.readouterr()
    assert "xdr_alertz: no installed pack declares this source" in captured.err
    assert "held out: xdr_alertz (typo)" in captured.out


def test_managed_scopes_the_release_to_this_hosts_sources(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two hosts converge as wh_ingest. The enclave holds nothing and must not
    release the warehouse host's xdr_alerts hold-out on every converge."""
    _use(monkeypatch, _Conn())
    released: list[str] = []
    monkeypatch.setattr(holdout, "hold", lambda c, s, r: False)
    monkeypatch.setattr(holdout, "my_hold_outs", lambda c: ["wazuh", "xdr_alerts"])
    monkeypatch.setattr(holdout, "release", lambda c, s: released.append(s) or True)

    assert holdout.main(["sync", "--managed", "wazuh", "--reason", "listed"]) == 0

    assert released == ["wazuh"]
    assert capsys.readouterr().out.splitlines() == ["released: wazuh", "changed: true"]


def test_a_hold_out_outside_managed_is_refused_before_connecting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(holdout, "_connect", lambda: pytest.fail("connected"))
    with pytest.raises(SystemExit):
        holdout.main(["sync", "xdr_alerts", "--managed", "wazuh", "--reason", "r"])
    assert "held out but not in --managed: xdr_alerts" in capsys.readouterr().err
