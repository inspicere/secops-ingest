"""Pluggable connector, target and dashboard bundles.

Third parties add a vendor without forking by registering an entry point::

    [project.entry-points."secops_ingest.packs"]
    knowbe4 = "secops_pack_knowbe4:PACK"
"""

from __future__ import annotations

from .model import Pack
from .registry import (
    ENTRY_POINT_GROUP,
    AmbiguousSource,
    DuplicatePack,
    DuplicateTarget,
    UnknownSource,
    all_targets,
    discover,
    resolve_source,
)
from .version import InvalidVersionSpec

__all__ = [
    "ENTRY_POINT_GROUP",
    "AmbiguousSource",
    "DuplicatePack",
    "DuplicateTarget",
    "InvalidVersionSpec",
    "Pack",
    "UnknownSource",
    "all_targets",
    "discover",
    "resolve_source",
]
