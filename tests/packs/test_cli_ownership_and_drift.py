"""`enable --state-only`, the schema-owner hint, and version drift in `list`.

Without a database: psycopg.connect and packs/state.py are stubbed, as in
test_cli_lifecycle.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secops_ingest.packs.__main__ import main
from secops_ingest.packs.version import describe_drift


class _FakeConnection:
    def close(self) -> None:
        return None

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False


def test_state_only_records_enabled_without_applying_ddl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generated schema file already applied the DDL; the owner credential
    is then needed for the state rows (the pack's, and its sources' in
    control.source_state), not for CREATE in every raw schema."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    applied: list[str] = []
    recorded: list[tuple[str, str]] = []
    mirrored: list[str] = []
    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.apply_ddl", lambda conn, text: applied.append(text)
    )
    monkeypatch.setattr(
        "secops_ingest.packs.state.set_state",
        lambda conn, name, version, state: recorded.append((name, state)),
    )
    monkeypatch.setattr(
        "secops_ingest.packs.state.set_source_states",
        lambda conn, sources, state, reason: mirrored.append(state),
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["enable", "builtin", "--state-only"]) == 0
    assert applied == []
    assert recorded == [("builtin", "ENABLED")]
    assert mirrored == ["ENABLED"]


def test_enable_without_state_only_still_applies_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    applied: list[str] = []
    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.set_source_states", lambda conn, sources, state, reason: None
    )
    monkeypatch.setattr(
        "secops_ingest.packs.state.apply_ddl", lambda conn, text: applied.append(text)
    )
    monkeypatch.setattr(
        "secops_ingest.packs.state.set_state", lambda conn, name, version, state: None
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["enable", "builtin"]) == 0
    assert len(applied) == 2


@pytest.mark.parametrize("command", [["enable", "builtin"], ["disable", "builtin"]])
def test_a_worker_dsn_is_told_to_use_the_schema_owner(
    command: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _denied(*args: object, **kwargs: object) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for table pack")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.apply_ddl", _denied)
    monkeypatch.setattr("secops_ingest.packs.state.set_state", _denied)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://wh_ingest@reachable/db")

    assert main(command) == 1
    assert "schema-owner role" in capsys.readouterr().err


def test_other_failures_get_no_owner_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(*args: object, **kwargs: object) -> None:
        raise psycopg.errors.UndefinedTable("relation does not exist")

    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr("secops_ingest.packs.state.apply_ddl", _boom)
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["enable", "builtin"]) == 1
    assert "schema-owner" not in capsys.readouterr().err


# -- version drift ---------------------------------------------------------------


def test_drift_is_silent_when_versions_agree() -> None:
    assert describe_drift("0.1.0", "0.1.0") is None


def test_drift_says_which_way_round() -> None:
    assert "re-run `enable`" in (describe_drift("0.1.0", "0.2.0") or "")
    assert "OLDER" in (describe_drift("0.3.0", "0.2.0") or "")


def test_drift_still_reports_versions_it_cannot_order() -> None:
    assert describe_drift("0.1.0", "0.2.0rc1") == "warehouse records 0.1.0, installed is 0.2.0rc1"


def test_list_marks_a_pack_whose_recorded_version_differs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The trace a silent no-op upgrade leaves: recorded and installed disagree."""
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest.packs.state import PackState

    stored = PackState("builtin", "0.0.9", "ENABLED", datetime(2026, 1, 1, tzinfo=UTC), None)
    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.all_states", lambda conn: {"builtin": stored}
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "[+] ENABLED" in out
    assert "[!] version: warehouse records 0.0.9, installed is" in out


def test_list_is_quiet_about_versions_that_agree(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")
    from secops_ingest import __version__
    from secops_ingest.packs.state import PackState

    stored = PackState("builtin", __version__, "ENABLED", None, None)
    monkeypatch.setattr(psycopg, "connect", lambda dsn: _FakeConnection())
    monkeypatch.setattr(
        "secops_ingest.packs.state.all_states", lambda conn: {"builtin": stored}
    )
    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")

    assert main(["list"]) == 0
    assert "[!] version" not in capsys.readouterr().out
