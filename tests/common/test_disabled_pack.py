"""A stale timer for a disabled pack must write nothing."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import run as run_mod
from secops_ingest.packs.state import PackState


@contextmanager
def _fake_connect() -> Iterator[object]:
    """A trivial stand-in for `db.connect()`. Never touches a real database."""
    yield object()


class _Source:
    name = "wazuh"
    table = "raw_wazuh.alerts"

    def __init__(self) -> None:
        self.fetched = False
        self.authenticated = False

    def authenticate(self) -> object:
        self.authenticated = True
        return object()

    def fetch(self, creds: object, cursor: str | None):  # type: ignore[no-untyped-def]
        self.fetched = True
        return iter(())

    def to_row(self, record: dict[str, object], run_id: int) -> tuple[object, ...]:
        return ()

    def watermark_of(self, record: dict[str, object]) -> object:
        return None


def _stub_db(monkeypatch: pytest.MonkeyPatch, started: list[str]) -> None:
    """Wire up db.* so a full `execute()` run never needs a real database."""
    monkeypatch.setattr(run_mod.db, "connect", _fake_connect)
    monkeypatch.setattr(run_mod.db, "start_run", lambda conn, name: started.append(name) or 1)
    monkeypatch.setattr(run_mod.db, "get_watermark", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "finish_run", lambda *a, **k: None)


def test_disabled_pack_does_not_fetch_or_record_a_run(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    source = _Source()
    started: list[str] = []

    monkeypatch.setattr(run_mod.db, "start_run", lambda conn, name: started.append(name) or 1)
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: "DISABLED")
    monkeypatch.setattr(run_mod.db, "connect", _fake_connect)

    with caplog.at_level(logging.WARNING):
        result = run_mod.execute(source)

    assert result.status == "DISABLED"
    assert source.fetched is False, "a disabled source must not reach the vendor API"
    assert started == [], "a run that did not happen must not appear in run history"
    assert "wazuh" in caplog.text


def test_disabled_pack_does_not_authenticate(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A disabled source must not resolve credentials at all.

    `authenticate()` is what talks to the secret backend; skipping only
    `fetch` while still authenticating would mean a disabled pack still
    reaches out to the vault/Delinea/whatever backend for no reason.
    """
    source = _Source()
    started: list[str] = []
    _stub_db(monkeypatch, started)
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: "DISABLED")

    with caplog.at_level(logging.WARNING):
        result = run_mod.execute(source)

    assert result.status == "DISABLED"
    assert source.authenticated is False, "a disabled source must not resolve credentials"
    assert started == []


def test_enabled_pack_proceeds_and_fetches(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real check, exercised end to end: an ENABLED row must not block."""
    source = _Source()  # name = "wazuh", owned by the real builtin pack
    started: list[str] = []
    _stub_db(monkeypatch, started)

    monkeypatch.setattr(
        "secops_ingest.packs.state.get_state",
        lambda conn, name: PackState(
            name=name, version="0.1.0", state="ENABLED", enabled_at=None, disabled_at=None
        ),
    )

    result = run_mod.execute(source)

    assert result.status == "SUCCESS"
    assert source.fetched is True
    assert started == ["wazuh"]


def test_source_with_no_pack_proceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unregistered source is not this check's business."""

    class _UnregisteredSource(_Source):
        name = "not-a-registered-source"

    source = _UnregisteredSource()
    started: list[str] = []
    _stub_db(monkeypatch, started)

    result = run_mod.execute(source)

    assert result.status == "SUCCESS"
    assert source.fetched is True
    assert started == ["not-a-registered-source"]


def test_missing_pack_table_proceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A warehouse provisioned before this feature must not turn into an outage."""
    source = _Source()  # owned by the real builtin pack
    started: list[str] = []
    _stub_db(monkeypatch, started)

    # This is exactly what packs.state.get_state returns when control.pack
    # does not exist at all -- see its own UndefinedTable handling.
    monkeypatch.setattr("secops_ingest.packs.state.get_state", lambda conn, name: None)

    result = run_mod.execute(source)

    assert result.status == "SUCCESS"
    assert source.fetched is True
    assert started == ["wazuh"]
