"""Every connector the deployment schedules must import and expose SOURCE.

The metabase repo's CI installs this package at a pinned ref and asserts
exactly this for each scheduled source. Asserting it here too means the failure
arrives in the package's own test run rather than in someone's converge.
"""

from __future__ import annotations

import importlib

import pytest

pytest.importorskip("httpx", reason="needs the 'http' extra")

SCHEDULED = ["xsoar", "xdr", "xdr_alerts", "xdr_endpoints"]


@pytest.mark.parametrize("name", SCHEDULED)
def test_source_module_exposes_a_source(name: str) -> None:
    module = importlib.import_module(f"secops_ingest.sources.{name}")
    source = getattr(module, "SOURCE", None)
    assert source is not None, f"{name} defines no SOURCE"
    for attr in ("name", "table", "authenticate", "fetch", "to_row", "watermark_of"):
        assert hasattr(source, attr), f"{name}.SOURCE lacks {attr}"


@pytest.mark.parametrize("name", SCHEDULED)
def test_source_name_matches_its_module(name: str) -> None:
    """The CLI loads a connector by module name and the framework records runs
    by SOURCE.name. If they disagree, control.ingest_run attributes rows to a
    source nobody scheduled."""
    module = importlib.import_module(f"secops_ingest.sources.{name}")
    assert module.SOURCE.name == name


@pytest.mark.parametrize("name", SCHEDULED)
def test_every_source_writes_to_its_own_table(name: str) -> None:
    module = importlib.import_module(f"secops_ingest.sources.{name}")
    assert module.SOURCE.table.startswith("raw_")


def test_no_two_sources_share_a_table() -> None:
    tables = {}
    for name in SCHEDULED:
        module = importlib.import_module(f"secops_ingest.sources.{name}")
        assert module.SOURCE.table not in tables, (
            f"{name} and {tables.get(module.SOURCE.table)} both write "
            f"{module.SOURCE.table}")
        tables[module.SOURCE.table] = name


def test_every_transform_target_is_registered() -> None:
    """Every Target instance defined at module scope must be in TARGETS.

    An unregistered Target is unreachable code that no scheduler can invoke.
    """
    from secops_ingest.transform import targets as targets_module
    from secops_ingest.transform.base import Target

    # Collect all Target instances defined at module scope
    defined_targets = {
        name: obj
        for name, obj in vars(targets_module).items()
        if isinstance(obj, Target)
    }

    # Collect all registered targets
    registered_targets = set(targets_module.TARGETS.values())

    # Find any targets that are defined but not registered
    unregistered = [
        name for name, target in defined_targets.items()
        if target not in registered_targets
    ]

    assert not unregistered, (
        f"Unregistered transform targets: {', '.join(sorted(unregistered))}"
    )
