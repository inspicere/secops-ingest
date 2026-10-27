"""cli.main hands the configured provider to the run, and fails if a named backend is broken."""

from __future__ import annotations

import logging
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
    seen: dict[str, Any] = {"called": False}

    def execute(source: object, **kwargs: Any) -> _Result:
        seen["called"] = True
        seen.update(kwargs)
        return _Result()

    monkeypatch.setattr(cli, "_load_source", lambda name: object())
    monkeypatch.setattr(run_mod, "execute", execute)
    return seen


def test_the_configured_provider_is_handed_to_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = object()
    monkeypatch.setenv("SECOPS_SECRETS_BACKEND", "env")
    monkeypatch.setattr(cli, "get_provider", lambda: provider)
    seen = _record_execute(monkeypatch)

    assert cli.main(["wazuh"]) == 0
    assert seen["provider"] is provider


def test_an_unset_backend_runs_on_the_static_dsn_silently(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # No backend configured is the ordinary static-DSN case: no provider is
    # built, and nothing is logged as a problem.
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)

    def must_not_be_asked() -> object:
        raise AssertionError("get_provider must not run when no backend is set")

    monkeypatch.setattr(cli, "get_provider", must_not_be_asked)
    seen = _record_execute(monkeypatch)

    with caplog.at_level(logging.WARNING):
        assert cli.main(["wazuh"]) == 0
    assert seen["provider"] is None
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize(
    "error",
    [
        SecretError("requires a map_source provider"),
        RuntimeError("anything else that stops a backend being built"),
    ],
    ids=["secret-error", "other-error"],
)
def test_a_configured_backend_that_cannot_be_built_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    # A backend the operator named but that cannot be built is a misconfiguration.
    # Falling back to the static DSN would run on the wrong credentials, so the
    # run must fail whatever the exception type is.
    monkeypatch.setenv("SECOPS_SECRETS_BACKEND", "mapped")

    def broken() -> object:
        raise error

    monkeypatch.setattr(cli, "get_provider", broken)
    seen = _record_execute(monkeypatch)

    assert cli.main(["wazuh"]) == 1
    assert seen["called"] is False


def test_an_unbuildable_backend_is_recorded_not_only_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # It used to exit before start_run, so pipeline health saw only staleness.
    # The run is still refused; the failure now reaches the ledger, by the
    # source's own name rather than the reference the operator typed.
    monkeypatch.setenv("SECOPS_SECRETS_BACKEND", "mapped")

    def broken() -> object:
        raise SecretError("requires a map_source provider")

    class _Named:
        name = "wazuh"

    recorded: list[tuple[str, str]] = []
    monkeypatch.setattr(cli, "get_provider", broken)
    seen = _record_execute(monkeypatch)
    monkeypatch.setattr(cli, "_load_source", lambda name: _Named())
    monkeypatch.setattr(run_mod, "record_unstartable",
                        lambda source, reason: recorded.append((source, reason)) or True)

    assert cli.main(["builtin.wazuh"]) == 1
    assert seen["called"] is False
    assert recorded == [
        ("wazuh", "secret provider could not be built: SecretError: "
                  "requires a map_source provider"),
    ]
