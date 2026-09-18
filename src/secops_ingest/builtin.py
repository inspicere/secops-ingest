"""The connectors and targets that ship in core, expressed as a pack.

Core's own sources go through the same registry as everyone else's, so there is
one code path and no "is this built in?" branch at any call site. This mirrors
how secops_ingest.secrets merges its built-in backends with entry points.

Core is not registered as an entry point because the test suite runs from src/
without installing the package, which would leave it undiscoverable in CI.
"""

from __future__ import annotations

import pkgutil

from . import __version__
from . import sources as _sources
from .packs.model import Pack
from .transform.targets import TARGETS


def _discover_sources() -> dict[str, str]:
    """Every connector module in `sources/`, as lazy "module:attr" references.

    Enumerated rather than listed. A hand-written list is a second place to
    forget: a connector added to `sources/` but not to that list imports fine,
    tests fine, and is invisible to the CLI as "unknown source" -- which is
    exactly what happened when the Cortex connectors landed alongside this
    registry.

    `pkgutil.iter_modules` reads the directory and does NOT import anything, so
    this stays safe on a core-only install where httpx is absent. Modules whose
    name starts with an underscore are shared helpers, not connectors.
    """
    return {
        name: f"secops_ingest.sources.{name}:SOURCE"
        for _finder, name, ispkg in pkgutil.iter_modules(_sources.__path__)
        if not ispkg and not name.startswith("_")
    }


PACK = Pack(
    name="builtin",
    version=__version__,
    # Core is compatible with itself by definition.
    requires_core=">=0",
    sources=_discover_sources(),
    # Derived from TARGETS rather than listed again, so a target added there is
    # never invisible to the CLI: production and the test suite now read the
    # same declaration.
    targets=tuple(TARGETS.values()),
)
