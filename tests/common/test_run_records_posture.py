from __future__ import annotations

from typing import Any

import pytest

# Needs the 'postgres' extra: common.run reaches psycopg through common.db.
pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import run as run_mod  # noqa: E402


class _EmptySource:
    name = "wazuh"
    table = "raw_wazuh.alerts"

    def authenticate(self) -> object:
        return object()

    def fetch(self, creds: object, cursor: str | None) -> Any:
        return iter(())

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return ()

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return None


class _FakeConn:
    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Provider:
    class _P:
        value = "assured"

    posture = _P()


def test_an_ingest_run_is_started_with_the_provider_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, Any] = {}

    def start_run(conn: object, source: str, *, posture: str | None = None) -> int:
        recorded["posture"] = posture
        return 1

    monkeypatch.setattr(run_mod.db, "connect", lambda: _FakeConn())
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "start_run", start_run)
    monkeypatch.setattr(run_mod.db, "get_watermark", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "finish_run", lambda *a, **k: None)

    run_mod.execute(_EmptySource(), provider=_Provider())

    assert recorded["posture"] == "assured"
