"""Pluggable connector, target and dashboard bundles.

Third parties add a vendor without forking by registering an entry point::

    [project.entry-points."secops_ingest.packs"]
    knowbe4 = "secops_pack_knowbe4:PACK"
"""

from __future__ import annotations

from .model import Pack
from .registry import ENTRY_POINT_GROUP, DuplicatePack, discover
from .version import InvalidVersionSpec, matches, parse_version

__all__ = [
    "ENTRY_POINT_GROUP",
    "DuplicatePack",
    "InvalidVersionSpec",
    "Pack",
    "discover",
    "matches",
    "parse_version",
]
