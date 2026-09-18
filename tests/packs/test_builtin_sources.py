"""The builtin pack registers every connector that exists, without importing one.

The regression: the Cortex connectors were added to `sources/` on one branch
while the pack registry was built on another. Both merged cleanly, every test
passed, and `secops-ingest xsoar` still failed as "unknown source" -- because
the pack's source list was hand-written and nobody had a reason to edit it.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

from secops_ingest.builtin import PACK
from secops_ingest.packs.registry import resolve_source

_SOURCES_DIR = pathlib.Path(__file__).resolve().parents[2] / "src" / "secops_ingest" / "sources"


def _connector_modules() -> set[str]:
    """Filenames on disk, independent of the code under test."""
    return {
        path.stem
        for path in _SOURCES_DIR.glob("*.py")
        if not path.stem.startswith("_")
    }


def test_every_connector_module_is_registered() -> None:
    assert set(PACK.sources) == _connector_modules()


def test_shared_helpers_are_not_registered_as_connectors() -> None:
    # _cortex.py holds auth shared by four connectors; it exposes no SOURCE.
    assert not any(name.startswith("_") for name in PACK.sources)


def test_references_are_lazy_strings() -> None:
    for name in PACK.sources:
        assert PACK.sources[name] == f"secops_ingest.sources.{name}:SOURCE"


def test_building_the_pack_imports_no_connector() -> None:
    """Discovery must work on a core-only install, where httpx is absent.

    Checked in a fresh interpreter rather than this one: by the time the suite
    reaches here, other tests have already imported connectors, so asserting
    against the current sys.modules would prove nothing.
    """
    probe = (
        "import sys; import secops_ingest.builtin as b; "
        "assert b.PACK.sources, 'no sources discovered'; "
        "leaked = [m for m in sys.modules if m.startswith('secops_ingest.sources.')]; "
        "assert not leaked, leaked; "
        "assert 'httpx' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,  # the assertion below reports stderr, which is the useful failure
        cwd=_SOURCES_DIR.parents[1],
    )
    assert result.returncode == 0, result.stderr


def test_scheduled_cortex_sources_resolve_by_bare_name() -> None:
    # These four are what the deployment schedules; bare names are what the
    # systemd units pass.
    for name in ("xsoar", "xdr", "xdr_alerts", "xdr_endpoints"):
        assert resolve_source(name) == f"secops_ingest.sources.{name}:SOURCE"
