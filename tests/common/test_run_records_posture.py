from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.common import run as run_mod
from secops_ingest.common.run import current_posture


class WithPosture:
    class _P:
        value = "assured"

    posture = _P()


class WithoutPosture:
    pass


class Raising:
    @property
    def posture(self) -> str:
        raise RuntimeError("backend unreachable")


def test_reads_the_posture_from_a_mapped_provider():
    assert current_posture(WithPosture()) == "assured"


def test_a_provider_without_a_posture_records_none():
    assert current_posture(WithoutPosture()) is None


def test_a_failure_to_read_posture_does_not_fail_the_run():
    # The posture is a diagnostic. A run that ingested correctly must not be
    # recorded as FAILED because a label could not be determined.
    assert current_posture(Raising()) is None


def test_none_provider_records_none():
    assert current_posture(None) is None


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

    run_mod.execute(_EmptySource(), provider=WithPosture())

    assert recorded["posture"] == "assured"
