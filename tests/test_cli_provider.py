"""cli.main hands the configured secret provider to the run, and survives its absence."""

from __future__ import annotations

from typing import Any

import pytest

# Needs the 'postgres' extra: cli.main reaches psycopg through common.run.
pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest import cli  # noqa: E402
from secops_ingest.common import run as run_mod  # noqa: E402
from secops_ingest.secrets import SecretError  # noqa: E402


class _Result:
    status = "SUCCESS"
    rows_read = 0
    rows_written = 0


def _record_execute(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def execute(source: object, **kwargs: Any) -> _Result:
        seen.update(kwargs)
        return _Result()

    monkeypatch.setattr(cli, "_load_source", lambda name: object())
    monkeypatch.setattr(run_mod, "execute", execute)
    return seen


def test_the_configured_provider_is_handed_to_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = object()
    monkeypatch.setattr(cli, "get_provider", lambda: provider)
    seen = _record_execute(monkeypatch)

    assert cli.main(["wazuh"]) == 0
    assert seen["provider"] is provider


def test_no_configured_provider_runs_on_the_static_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A backend that cannot be constructed must not fail the run. The run then
    # takes the SECOPS_DB_DSN path, exactly as it did before providers existed.
    def unavailable() -> object:
        raise SecretError("unknown secrets backend 'nope'")

    monkeypatch.setattr(cli, "get_provider", unavailable)
    seen = _record_execute(monkeypatch)

    assert cli.main(["wazuh"]) == 0
    assert seen["provider"] is None
