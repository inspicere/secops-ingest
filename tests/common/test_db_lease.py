# tests/common/test_db_lease.py
from __future__ import annotations

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common.db import resolve_dsn  # noqa: E402


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
    assert resolve_dsn() == "dbname=w host=h user=u password=p"


def test_a_lease_builds_the_dsn_from_the_base_and_the_credential(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv(
        "SECOPS_DB_BASE_DSN", "host=warehouse dbname=secops_warehouse sslmode=require"
    )
    leaser = FakeLeaser({"username": "v-cert-ingest-abc", "password": "leased-pw"})
    dsn = resolve_dsn(leaser)
    assert leaser.asked == ["database/creds/ingest"]
    assert "user='v-cert-ingest-abc'" in dsn
    assert "password='leased-pw'" in dsn
    assert "host=warehouse" in dsn


def test_a_lease_takes_precedence_over_a_static_dsn(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_DSN", "dbname=w user=static password=static")
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    dsn = resolve_dsn(FakeLeaser({"username": "u", "password": "p"}))
    assert "static" not in dsn


def test_values_with_spaces_or_quotes_are_escaped(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    dsn = resolve_dsn(FakeLeaser({"username": "u", "password": "a b'c\\d"}))
    assert "password='a b\\'c\\\\d'" in dsn


def test_a_lease_without_a_provider_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    with pytest.raises(RuntimeError, match="SECOPS_DB_LEASE is set but no provider"):
        resolve_dsn(None)


def test_a_lease_without_a_base_dsn_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.delenv("SECOPS_DB_BASE_DSN", raising=False)
    with pytest.raises(RuntimeError, match="SECOPS_DB_BASE_DSN"):
        resolve_dsn(FakeLeaser({"username": "u", "password": "p"}))


def test_a_lease_missing_a_field_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    with pytest.raises(RuntimeError, match="username and password"):
        resolve_dsn(FakeLeaser({"username": "u"}))


def test_neither_configured_is_the_existing_error(monkeypatch):
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    with pytest.raises(RuntimeError, match="SECOPS_DB_DSN is not set"):
        resolve_dsn()


def test_the_leased_password_is_registered_for_redaction(monkeypatch):
    from secops_ingest import redaction

    redaction._REGISTRY.clear()
    monkeypatch.setenv("SECOPS_DB_LEASE", "database/creds/ingest")
    monkeypatch.setenv("SECOPS_DB_BASE_DSN", "host=h dbname=w")
    resolve_dsn(FakeLeaser({"username": "u", "password": "leased-password-value"}))
    assert redaction.scrub("x leased-password-value y") != "x leased-password-value y"
    redaction._REGISTRY.clear()
