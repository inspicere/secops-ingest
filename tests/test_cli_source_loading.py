"""cli._load_source distinguishes an unregistered source from a broken one."""

from __future__ import annotations

import pytest

from secops_ingest import cli


def test_unknown_source_exits_with_a_named_message() -> None:
    with pytest.raises(SystemExit, match="unknown source: nope"):
        cli._load_source("nope")


def test_import_error_inside_a_connector_is_not_reported_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The failure this protects against: a connector missing an optional
    # dependency reported as "unknown source", sending someone to debug the
    # module name instead of the missing extra.
    monkeypatch.setattr(
        cli, "resolve_source", lambda ref: "secops_ingest.tests_missing_module:SOURCE"
    )
    with pytest.raises(ModuleNotFoundError):
        cli._load_source("wazuh")


def test_missing_attribute_names_the_module_and_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "resolve_source", lambda ref: "secops_ingest.redaction:NOPE")
    with pytest.raises(SystemExit, match="does not define NOPE"):
        cli._load_source("wazuh")
