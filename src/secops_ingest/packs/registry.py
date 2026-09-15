"""Pack discovery.

Built-ins merged with entry points, the same shape secops_ingest.secrets uses
for secret backends.

Failure policy is deliberately split. A pack that cannot be used is SKIPPED with
a loud log, because one broken pack must not take down every other pack's
timers; the operator finds out through `pack list` or through that source
failing by name. A NAME COLLISION is fatal, because silently preferring one of
two packs would make behaviour depend on entry-point iteration order.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from .. import __version__
from .model import Pack
from .version import InvalidVersionSpec, matches

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "secops_ingest.packs"


class DuplicatePack(RuntimeError):
    """Two distributions register a pack under the same name."""


def _origin(ep: Any) -> str:
    """Best available description of where an entry point came from."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    return str(name) if name else str(getattr(ep, "value", ep))


def discover(
    *,
    core_version: str | None = None,
    extra: Iterable[EntryPoint] | None = None,
) -> dict[str, Pack]:
    """Return every usable pack, keyed by name.

    Args:
        core_version: override the running core version. Tests use this.
        extra: additional entry points to consider. Tests use this, because the
            package is not installed during the test run and therefore registers
            nothing.

    Raises:
        DuplicatePack: two packs claim the same name.
    """
    from ..builtin import PACK as BUILTIN

    core = core_version or __version__
    found: dict[str, Pack] = {BUILTIN.name: BUILTIN}
    origins: dict[str, str] = {BUILTIN.name: "secops-ingest (core)"}

    points: list[Any] = list(entry_points(group=ENTRY_POINT_GROUP))
    if extra is not None:
        points.extend(extra)

    for ep in points:
        origin = _origin(ep)
        try:
            pack = ep.load()
        except Exception:
            log.exception(
                "pack entry point %r from %s failed to load; skipping", ep.name, origin
            )
            continue

        if not isinstance(pack, Pack):
            log.error(
                "pack entry point %r from %s is %s, not a Pack; skipping",
                ep.name, origin, type(pack).__name__,
            )
            continue

        if pack.name in origins:
            raise DuplicatePack(
                f"pack {pack.name!r} is registered by both "
                f"{origins[pack.name]} and {origin}"
            )

        origins[pack.name] = origin

        try:
            usable = matches(core, pack.requires_core)
        except InvalidVersionSpec as exc:
            log.error("pack %r declares an unusable core range: %s; skipping", pack.name, exc)
            continue

        if not usable:
            log.warning(
                "pack %r requires core %s but core is %s; skipping. Its sources will "
                "report as unknown until this is resolved.",
                pack.name, pack.requires_core, core,
            )
            continue

        found[pack.name] = pack

    return found


class UnknownSource(LookupError):
    """No registered pack provides the named source."""


class AmbiguousSource(LookupError):
    """More than one pack provides a source under this bare name."""


def resolve_source(ref: str, packs: Mapping[str, Pack] | None = None) -> str:
    """Return the "module:attr" target for a source reference.

    Accepts `pack.source`, or a bare `source` when exactly one pack provides it.
    Bare names are what existing systemd units and Ansible inventories pass, so
    they keep working; a bare name that two packs claim is an error rather than
    a coin flip.
    """
    registry = discover() if packs is None else packs

    if "." in ref:
        pack_name, _, source_name = ref.partition(".")
        pack = registry.get(pack_name)
        if pack is None or source_name not in pack.sources:
            raise UnknownSource(f"unknown source: {ref}")
        return pack.sources[source_name]

    hits = [(pack.name, pack.sources[ref]) for pack in registry.values() if ref in pack.sources]
    if not hits:
        raise UnknownSource(f"unknown source: {ref}")
    if len(hits) > 1:
        candidates = ", ".join(sorted(f"{pack_name}.{ref}" for pack_name, _ in hits))
        raise AmbiguousSource(
            f"source {ref!r} is provided by more than one pack; name one of: {candidates}"
        )
    return hits[0][1]
