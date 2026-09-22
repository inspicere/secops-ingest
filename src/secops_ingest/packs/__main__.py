"""python -m secops_ingest.packs {list,enable,disable}

`list` reports what this environment can see. Enabled/disabled state lives in
the warehouse and is not read here, so `list` needs no database and no
optional dependency -- it is the command you reach for when the install is
broken, so it must not need the thing that might be broken.

`enable`/`disable` record a pack's state in `control.pack` and, for `enable`,
create the pack's schema. Both need a database and the `postgres` extra, so
`packs/state.py` and `psycopg` are imported lazily, inside their handlers
only, so that `list` keeps working with neither installed.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from importlib.metadata import entry_points

from .. import __version__
from ..redaction import RedactingFilter
from .model import Pack
from .registry import ENTRY_POINT_GROUP, DuplicatePack, DuplicateTarget, all_targets, discover
from .version import InvalidVersionSpec, matches

log = logging.getLogger(__name__)


def _configure_logging() -> None:
    # Installed before any registry call: a pack that raises on load is logged
    # by registry.py through this handler, and secrets can end up embedded in
    # an import error just as easily as in a connector's own logging.
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
    )


def _discover_packs() -> dict[str, Pack] | None:
    """discover(), reporting a name collision as one clean stderr line.

    Every subcommand touches the registry, so they all need this; returns
    None on failure so a caller can just check for that and return 1.
    """
    try:
        return discover()
    except (DuplicatePack, DuplicateTarget) as exc:
        print(str(exc), file=sys.stderr)
        return None


def _explain_unregistered(name: str) -> str:
    """Why `name` did not come back from discover(): unknown, or dropped for a
    core-version mismatch.

    discover() silently skips an incompatible pack -- deliberately, so one
    third-party pack's version skew cannot take every other pack's listing
    down with it -- and that silence is exactly what would make "unknown
    pack" a misleading message here. This re-scans entry points, the same
    ones discover() itself sees, purely to explain an absence; it changes
    nothing, and callers only reach it once discover() has already failed to
    find the pack.
    """
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            candidate = ep.load()
        except Exception:
            log.exception("pack entry point %r failed to load while explaining an absence", ep.name)
            continue
        if not isinstance(candidate, Pack) or candidate.name != name:
            continue
        try:
            compatible = matches(__version__, candidate.requires_core)
        except InvalidVersionSpec:
            continue
        if not compatible:
            return (
                f"pack {name!r} requires core {candidate.requires_core}, "
                f"but this install is core {__version__}"
            )
    return f"unknown pack: {name!r}"


def _require_dsn() -> str | None:
    dsn = os.environ.get("SECOPS_DB_DSN")
    if not dsn:
        print("SECOPS_DB_DSN is not set", file=sys.stderr)
        return None
    return dsn


def _cmd_list() -> int:
    packs = _discover_packs()
    if packs is None:
        return 1
    try:
        targets = all_targets(packs)
    except (DuplicatePack, DuplicateTarget) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for name in sorted(packs):
        pack = packs[name]
        # Safe to compare Target objects by value: all_targets() enforces
        # global uniqueness of target.name across packs before this runs.
        owned = sorted(t for t, target in targets.items() if target in pack.targets)
        print(f"{name}  {pack.version}  (core {pack.requires_core})")
        print(f"    sources: {', '.join(sorted(pack.sources)) or '-'}")
        print(f"    targets: {', '.join(owned) or '-'}")
    return 0


def _cmd_enable(name: str) -> int:
    # Resolved from the registry before anything touches a connection: the
    # unknown-pack failure must be about the name, not about a DSN that
    # happens not to resolve. See test_enable_unknown_pack_names_it.
    #
    # The control row is written strictly last, after both DDL applications have
    # committed, so a failure in between can never leave a row claiming ENABLED
    # with no tables behind it -- and the reverse (re-running after a partial
    # failure) self-heals, because every statement below is CREATE ... IF NOT
    # EXISTS; verified against the live database.
    packs = _discover_packs()
    if packs is None:
        return 1
    pack = packs.get(name)
    if pack is None:
        print(_explain_unregistered(name), file=sys.stderr)
        return 1

    dsn = _require_dsn()
    if dsn is None:
        return 1

    from ..schema import control_sql, ddl_for_targets

    try:
        # Pure text generation -- no side effect -- so a target whose
        # raw_table is not schema-qualified is caught here, before any DDL
        # has been applied and before the control row is written. Nothing is
        # left half-applied. Does not touch dashboards -- those are spec §4
        # and do not exist yet.
        target_ddl = ddl_for_targets(pack.targets)
    except ValueError as exc:
        print(f"pack {name!r}: {exc}", file=sys.stderr)
        return 1

    import psycopg

    from . import state as pack_state

    try:
        with psycopg.connect(dsn) as conn:
            pack_state.apply_ddl(conn, control_sql())
            pack_state.apply_ddl(conn, target_ddl)
            pack_state.set_state(conn, name, pack.version, "ENABLED")
    except psycopg.Error as exc:
        print(f"could not enable pack {name!r}: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_disable(name: str) -> int:
    packs = _discover_packs()
    if packs is None:
        return 1
    pack = packs.get(name)

    dsn = _require_dsn()
    if dsn is None:
        return 1

    import psycopg

    from . import state as pack_state

    try:
        with psycopg.connect(dsn) as conn:
            if pack is not None:
                # Registered: converge to DISABLED unconditionally, whether or
                # not it was ever enabled before. control_sql() only creates
                # control.pack (and its siblings) -- never a raw_* schema --
                # so a pack that was never enabled still gets a row here
                # without this ever looking like "data was touched".
                from ..schema import control_sql

                pack_state.apply_ddl(conn, control_sql())
                pack_state.set_state(conn, name, pack.version, "DISABLED")
                return 0

            existing = pack_state.get_state(conn, name)
            if existing is None:
                print(_explain_unregistered(name), file=sys.stderr)
                return 1
            # Unregistered but has history (e.g. the pack was uninstalled):
            # disable it without guessing at a version it no longer declares.
            pack_state.set_state(conn, name, existing.version, "DISABLED")
    except psycopg.Error as exc:
        print(f"could not disable pack {name!r}: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.packs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="show every pack this install can see")
    enable_parser = subparsers.add_parser("enable", help="enable a pack in the warehouse")
    enable_parser.add_argument("name")
    disable_parser = subparsers.add_parser("disable", help="disable a pack in the warehouse")
    disable_parser.add_argument("name")
    args = parser.parse_args(argv)

    _configure_logging()

    if args.command == "list":
        return _cmd_list()
    if args.command == "enable":
        return _cmd_enable(args.name)
    return _cmd_disable(args.name)


if __name__ == "__main__":
    sys.exit(main())
