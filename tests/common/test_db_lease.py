# tests/common/test_db_lease.py
from __future__ import annotations

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from secops_ingest.common.db import connect, resolve_conninfo  # noqa: E402


class FakeLeaser:
    def __init__(self, data):
        self.data = data
        self.asked: list[str] = []

    def lease(self, path: str):
        self.asked.append(path)
        return self.data


def test_static_dsn_is_used_when_no_lease_is_configured(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_DSN", "dbname=w host=h user=u password=p")
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    assert resolve_conninfo() == ("dbname=w host=h user=u password=p", {})


def test_a_lease_builds_the_dsn_from_the_base_and_the_credential(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv(
        "SECOPS_DB_BASE_DSN", "host=warehouse dbname=secops_warehouse sslmode=require"
    )
    leaser = FakeLeaser({"username": "v-cert-ingest-abc", "password": "leased-pw"})
    base, creds = resolve_conninfo(leaser)
    assert leaser.asked == ["database/creds/ingest"]
    assert creds == {"user": "v-cert-ingest-abc", "password": "leased-pw"}
    assert base == "host=warehouse dbname=secops_warehouse sslmode=require"


def test_a_lease_takes_precedence_over_a_static_dsn(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_DSN", "dbname=w user=static password=static")
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    base, creds = resolve_conninfo(FakeLeaser({"username": "u", "password": "p"}))
    assert "static" not in base + str(creds)


def _merged(monkeypatch, base, password):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", base)
    conninfo, creds = resolve_conninfo(FakeLeaser({"username": "u", "password": password}))
    return conninfo_to_dict(make_conninfo(conninfo, **creds))


NASTY = "a b'c\\d"


@pytest.mark.parametrize(
    "base",
    [
        "host=h dbname=w",
        "postgresql://h/w?sslmode=require",  # URI form: string concatenation broke here
    ],
)
def test_a_password_with_quote_and_backslash_round_trips_into_either_base_form(
    monkeypatch, base
):
    merged = _merged(monkeypatch, base, NASTY)
    assert merged["password"] == NASTY
    assert merged["user"] == "u"
    assert merged["host"] == "h"


def test_connect_passes_credentials_as_arguments_not_in_the_string(monkeypatch):
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
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "postgresql://h/w")
    with connect(FakeLeaser({"username": "u", "password": NASTY})):
        pass
    assert seen["conninfo"] == "postgresql://h/w"
    assert seen["kwargs"] == {"user": "u", "password": NASTY}


def test_a_lease_without_a_provider_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    with pytest.raises(RuntimeError, match="SECOPS_DB_LEASE is set but no provider"):
        resolve_conninfo(None)


def test_a_lease_without_a_base_dsn_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.delenv("SECOPS_DB_BASE_DSN", raising=False)
    with pytest.raises(RuntimeError, match="SECOPS_DB_BASE_DSN"):
        resolve_conninfo(FakeLeaser({"username": "u", "password": "p"}))


def test_a_lease_missing_a_field_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    with pytest.raises(RuntimeError, match="username and password"):
        resolve_conninfo(FakeLeaser({"username": "u"}))


def test_neither_configured_is_the_existing_error(monkeypatch):
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    with pytest.raises(RuntimeError, match="SECOPS_DB_DSN is not set"):
        resolve_conninfo()


def test_the_leased_password_is_registered_for_redaction(monkeypatch):
    from secops_ingest import redaction

    redaction._REGISTRY.clear()
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    resolve_conninfo(FakeLeaser({"username": "u", "password": "leased-password-value"}))
    assert redaction.scrub("x leased-password-value y") != "x leased-password-value y"
    redaction._REGISTRY.clear()
