# tests/common/test_db_stored_password.py
"""SECOPS_DB_PASSWORD_SECRET: a stored, rotated password read per connection."""
from __future__ import annotations

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common.db import connect, resolve_conninfo  # noqa: E402

BASE = "host=warehouse dbname=secops_warehouse user=wh_ingest sslmode=verify-full"


class FakeProvider:
    def __init__(self, values):
        self.values = values
        self.asked: list[str] = []

    def get(self, name: str) -> str:
        self.asked.append(name)
        return self.values[name]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("SECOPS_DB_DSN", "SECOPS_DB_LEASE", "SECOPS_DB_PASSWORD_SECRET",
                "SECOPS_DB_BASE_DSN"):
        monkeypatch.delenv(var, raising=False)


def _configure(monkeypatch, base=BASE):
    monkeypatch.setenv("SECOPS_DB_PASSWORD_SECRET", "warehouse_ingest_password")
    if base is not None:
        monkeypatch.setenv("SECOPS_DB_BASE_DSN", base)


def test_the_password_is_read_by_name_for_the_user_the_base_names(monkeypatch):
    _configure(monkeypatch)
    provider = FakeProvider({"warehouse_ingest_password": "stored-pw"})
    assert resolve_conninfo(provider) == (BASE, {"password": "stored-pw"})
    assert provider.asked == ["warehouse_ingest_password"]


# Per connection, not cached anywhere here: a rotation in the store reaches the
# next run without a converge.
def test_each_connection_reads_the_current_value(monkeypatch):
    _configure(monkeypatch)
    provider = FakeProvider({"warehouse_ingest_password": "before"})
    assert resolve_conninfo(provider)[1] == {"password": "before"}
    provider.values["warehouse_ingest_password"] = "after"
    assert resolve_conninfo(provider)[1] == {"password": "after"}


def test_a_static_dsn_is_not_consulted(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setenv("SECOPS_DB_DSN", "dbname=w user=static password=static")
    base, creds = resolve_conninfo(FakeProvider({"warehouse_ingest_password": "p"}))
    assert "static" not in base + str(creds)


def test_lease_and_stored_password_together_are_refused(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    with pytest.raises(RuntimeError, match="both set"):
        resolve_conninfo(FakeProvider({}))


def test_without_a_base_dsn_is_a_clear_error(monkeypatch):
    _configure(monkeypatch, base=None)
    with pytest.raises(RuntimeError, match="SECOPS_DB_BASE_DSN"):
        resolve_conninfo(FakeProvider({"warehouse_ingest_password": "p"}))


def test_without_a_provider_is_a_clear_error(monkeypatch):
    _configure(monkeypatch)
    with pytest.raises(RuntimeError, match="no secret provider"):
        resolve_conninfo(None)


def test_an_empty_password_is_refused(monkeypatch):
    _configure(monkeypatch)
    with pytest.raises(RuntimeError, match="empty database password"):
        resolve_conninfo(FakeProvider({"warehouse_ingest_password": ""}))


def test_the_password_is_registered_for_redaction(monkeypatch):
    from secops_ingest import redaction

    redaction._REGISTRY.clear()
    _configure(monkeypatch)
    resolve_conninfo(FakeProvider({"warehouse_ingest_password": "stored-password-value"}))
    assert redaction.scrub("x stored-password-value y") != "x stored-password-value y"
    redaction._REGISTRY.clear()


def test_connect_passes_only_the_password_as_an_argument(monkeypatch):
    import psycopg

    seen = {}

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_connect(conninfo, **kwargs):
        seen["conninfo"], seen["kwargs"] = conninfo, kwargs
        return Conn()

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    _configure(monkeypatch)
    with connect(FakeProvider({"warehouse_ingest_password": "a b'c\\d"})):
        pass
    assert seen == {"conninfo": BASE, "kwargs": {"password": "a b'c\\d"}}
