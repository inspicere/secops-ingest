"""The connectors and targets that ship in core, expressed as a pack.

Core's own sources go through the same registry as everyone else's, so there is
one code path and no "is this built in?" branch at any call site. This mirrors
how secops_ingest.secrets merges its built-in backends with entry points.

Core is not registered as an entry point because the test suite runs from src/
without installing the package, which would leave it undiscoverable in CI.
"""

from __future__ import annotations

from . import __version__
from .packs.model import Pack
from .transform.targets import TARGETS

PACK = Pack(
    name="builtin",
    version=__version__,
    # Core is compatible with itself by definition.
    requires_core=">=0",
    sources={
        "example": "secops_ingest.sources.example:SOURCE",
        "wazuh": "secops_ingest.sources.wazuh:SOURCE",
        "defectdojo": "secops_ingest.sources.defectdojo:SOURCE",
    },
    # Derived from TARGETS rather than listed again, so a target added there is
    # never invisible to the CLI: production and the test suite now read the
    # same declaration.
    targets=tuple(TARGETS.values()),
)
