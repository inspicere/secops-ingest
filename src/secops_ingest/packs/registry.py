"""Pack discovery.

Built-ins merged with entry points, the same shape secops_ingest.secrets uses
for secret backends.

Failure policy: a pack that cannot be used is SKIPPED with a loud log, because
one broken pack must not take down every other pack's timers; the operator
finds out through `pack list` or through that source failing by name.

That now includes a NAME COLLISION between two third-party packs. It used to be
fatal, on the reasoning that silently preferring one would make behaviour
depend on entry-point iteration order -- which is true, and is why neither is
preferred: BOTH are skipped. What fatal actually bought was every ingest timer,
transform and schema emission exiting 1 on startup, including built-in sources
nothing to do with the collision, because an old copy of one pack was left in
the venv. Skipping both keeps the ambiguity out of the running system and keeps
everything else running; `pack list` reports the collision and exits non-zero,
so it is not quiet.

A collision against `builtin` is resolved the other way: core is seeded
deterministically before entry points are even looked up, so there is no
ordering ambiguity to protect against -- core always wins, and the offending
pack is skipped.

WHICH DISTRIBUTIONS MAY LOAD AT ALL. Loading an entry point runs its code in
the process that holds resolved secrets. `SECOPS_ALLOWED_PACKS`, when set, is a
comma-separated list of distribution names; an entry point from any other
distribution is skipped with a WARNING *before* it is loaded, so its code never
runs. Set but empty means "no third-party packs" -- an allowlist that a
templating slip renders empty must fail closed, not open. Unset keeps the old
behaviour (every installed pack loads), and every pack that does load is
logged with its distribution and version, so what ran is on record either way.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING, Any

from .. import __version__
from ..schema import validate_identifier
from .model import Pack
from .version import InvalidVersionSpec, matches, parse_version

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the import lazy
    from ..transform.base import Target

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "secops_ingest.packs"

#: Comma-separated distribution names allowed to register packs. See the
#: module docstring.
ALLOWLIST_ENV = "SECOPS_ALLOWED_PACKS"


class DuplicatePack(RuntimeError):
    """Two distributions register a pack under the same name.

    No longer raised by discover(), which skips both instead; kept because
    callers still catch it, and because `pack list` reports the same condition.
    """


def allowed_distributions() -> frozenset[str] | None:
    """The allowlist from the environment, or None when there is none.

    Names are compared case-insensitively with `-` and `_` treated alike, the
    way pip itself compares distribution names, so `Vendor_Pack` and
    `vendor-pack` are the same entry.
    """
    raw = os.environ.get(ALLOWLIST_ENV)
    if raw is None:
        return None
    return frozenset(_normalise(name) for name in raw.split(",") if name.strip())


def _normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def entry_point_allowed(ep: Any, allowed: frozenset[str] | None) -> bool:
    """May this entry point be loaded? Decided from metadata alone, never by loading it."""
    if allowed is None:
        return True
    dist = getattr(getattr(ep, "dist", None), "name", None)
    return dist is not None and _normalise(str(dist)) in allowed


def _origin(ep: Any) -> str:
    """Best available description of where an entry point came from."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    return str(name) if name else str(getattr(ep, "value", ep))


def _with_version(ep: Any, origin: str) -> str:
    """`origin`, plus the distribution's version when the metadata has one."""
    version = getattr(getattr(ep, "dist", None), "version", None)
    return f"{origin} {version}" if version else origin


def discover(
    *,
    core_version: str | None = None,
    extra: Iterable[EntryPoint] | None = None,
    problems: list[str] | None = None,
) -> dict[str, Pack]:
    """Return every usable pack, keyed by name.

    Args:
        core_version: override the running core version. Tests use this.
        extra: additional entry points to consider. Tests use this, because the
            package is not installed during the test run and therefore registers
            nothing.
        problems: if given, a one-line description of every pack that was
            skipped for a reason an operator must fix (a collision, an
            allowlist refusal) is appended to it. `pack list` uses this to exit
            non-zero; the workers ignore it and keep running.

    Raises:
        InvalidVersionSpec: the running core version is not a plain numeric
            release, so no pack's `requires_core` could be checked against it.
    """
    from ..builtin import PACK as BUILTIN

    core = core_version or __version__
    try:
        parse_version(core)
    except InvalidVersionSpec as exc:
        raise InvalidVersionSpec(
            f"running core version {core!r} is unusable: {exc}"
        ) from exc

    found: dict[str, Pack] = {BUILTIN.name: BUILTIN}
    report = problems if problems is not None else []

    points: list[Any] = list(entry_points(group=ENTRY_POINT_GROUP))
    if extra is not None:
        points.extend(extra)

    allowed = allowed_distributions()

    # Every candidate is loaded and checked first, and only then are names
    # compared: a collision has to be judged on the full set, or the outcome
    # would again depend on which of the two happened to be iterated first.
    candidates: dict[str, list[tuple[Pack, str]]] = {}
    for ep in points:
        origin = _origin(ep)
        if not entry_point_allowed(ep, allowed):
            log.warning(
                "pack entry point %r from %s is not in %s; not loaded",
                ep.name, origin, ALLOWLIST_ENV,
            )
            report.append(f"pack entry point {ep.name!r} from {origin}: not in {ALLOWLIST_ENV}")
            continue
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

        if pack.name == BUILTIN.name:
            log.error(
                "pack entry point %r from %s collides with the core pack "
                "name %r; core wins and this pack is skipped. Rename it.",
                ep.name, origin, pack.name,
            )
            report.append(f"pack {pack.name!r} from {origin} collides with core; skipped")
            continue

        candidates.setdefault(pack.name, []).append((pack, _with_version(ep, origin)))

    for name, claims in candidates.items():
        if len(claims) > 1:
            origins = " and ".join(origin for _pack, origin in claims)
            message = (
                f"pack {name!r} is registered by both {origins}; skipping all of them "
                "until one is uninstalled. Every other pack keeps running."
            )
            log.error("%s", message)
            report.append(message)
            continue

        pack, origin = claims[0]
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

        log.info("loaded pack %r %s from %s", pack.name, pack.version, origin)
        found[pack.name] = pack

    return found


class UnknownSource(LookupError):
    """No registered pack provides the named source."""


class AmbiguousSource(LookupError):
    """More than one pack provides a source under this bare name."""


def _available_sources(registry: Mapping[str, Pack]) -> str:
    """Every qualified source reference, for an "available: ..." message."""
    names = sorted(
        f"{pack.name}.{source_name}"
        for pack in registry.values()
        for source_name in pack.sources
    )
    return ", ".join(names) if names else "-"


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
            raise UnknownSource(
                f"unknown source: {ref}; available: {_available_sources(registry)}"
            )
        return pack.sources[source_name]

    hits = [(pack.name, pack.sources[ref]) for pack in registry.values() if ref in pack.sources]
    if not hits:
        raise UnknownSource(
            f"unknown source: {ref}; available: {_available_sources(registry)}"
        )
    if len(hits) > 1:
        candidates = ", ".join(sorted(f"{pack_name}.{ref}" for pack_name, _ in hits))
        raise AmbiguousSource(
            f"source {ref!r} is provided by more than one pack; name one of: {candidates}"
        )
    return hits[0][1]


class DuplicateTarget(RuntimeError):
    """Two packs declare a transform target under the same name."""


def all_targets(
    packs: Mapping[str, Pack] | None = None, *, skip_collisions: bool = False
) -> dict[str, Target]:
    """Every transform target from every usable pack, keyed by target name.

    Target names become table names and CLI arguments, so a collision is never
    resolved by iteration order, and the name itself is validated here rather
    than in `Target.__post_init__` -- this is the boundary where every pack's
    targets actually meet the CLI and the warehouse.

    By default a collision raises DuplicateTarget. That is right for anything
    about to write or destroy by target name (`pack enable`, `pack drop`, the
    schema emitter), whose safety depends on the names being unique. A worker
    that only RUNS targets passes `skip_collisions=True`: every target claiming
    a colliding name is dropped with an ERROR naming both packs, and every
    other target keeps running -- the same policy discover() applies to pack
    names.
    """
    registry = discover() if packs is None else packs
    targets: dict[str, Target] = {}
    owners: dict[str, str] = {}
    colliding: set[str] = set()
    for pack in registry.values():
        for target in pack.targets:
            validate_identifier(target.name)
            if target.name in owners:
                message = (
                    f"transform target {target.name!r} is declared by both "
                    f"packs {owners[target.name]!r} and {pack.name!r}"
                )
                if not skip_collisions:
                    raise DuplicateTarget(message)
                log.error("%s; skipping both. Every other target keeps running.", message)
                colliding.add(target.name)
                continue
            targets[target.name] = target
            owners[target.name] = pack.name
    for name in colliding:
        targets.pop(name, None)
    return targets
