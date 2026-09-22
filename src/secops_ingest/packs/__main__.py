"""python -m secops_ingest.packs {list,enable,disable,drop}

`list` reports what this environment can see, and -- when it can -- what the
warehouse thinks. Its core report never needs a database or `psycopg`: it is
the command you reach for when the install is broken, so it must not need the
thing that might be broken. Without `SECOPS_DB_DSN`, or without `psycopg`
installed, it prints exactly what it always has, plus one line saying state
is unknown. With both, it also prints each registered pack's enabled/disabled
state, and separately flags any `control.pack` row belonging to a pack that
is not currently registered -- the "enabled but not installed" shape of a
half-finished upgrade.

`enable`/`disable` record a pack's state in `control.pack` and, for `enable`,
create the pack's schema. Both need a database and the `postgres` extra, so
`packs/state.py` and `psycopg` are imported lazily, inside their handlers
only, so that `list` keeps working with neither installed.

`drop` is the exception to this feature's whole design: every other verb is
recoverable ("disable, never drop" -- removal stops a pack and leaves the
warehouse intact), and `drop` is the deliberate, singular way to actually
destroy a pack's data. It always prints what it would drop (or, given the
flag, what it destroyed) and how many rows are in each table -- "0 rows" and
"4,000,000 rows" must not read the same to someone about to type the flag --
and it only drops anything when called with `--yes-destroy-data`. Without
that flag it exits non-zero: this is a refusal, not a report, and a script
that ignores the exit code must not then proceed as though the data were
gone.

`drop` also requires the pack to already be DISABLED: dropping data out from
under a still-running connector would leave it authenticating and failing
every interval once the tables it depends on are gone, and requiring the
disable first closes the window where a run in flight could race the drop.
The `control.pack` row itself is left behind, still DISABLED, rather than
deleted -- a deleted row reads as "never seen here", which is exactly the
state a surviving timer's PROCEED-by-default gate treats as safe to run.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Mapping
from importlib.metadata import entry_points
from typing import TYPE_CHECKING

from .. import __version__
from ..redaction import RedactingFilter
from ..schema import validate_identifier
from .model import Pack
from .registry import ENTRY_POINT_GROUP, DuplicatePack, DuplicateTarget, all_targets, discover
from .version import InvalidVersionSpec, matches

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the import lazy
    import psycopg
    from psycopg import sql

    from ..transform.base import Target
    from .state import PackState

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


def _discover_targets(packs: dict[str, Pack]) -> dict[str, Target] | None:
    """all_targets(packs), reporting a target-name collision as one clean stderr line.

    Every subcommand that is about to WRITE or DESTROY a pack's tables and
    control rows by target name -- `enable` and `drop`, not just `list` --
    needs this checked first. `drop`'s `DELETE ... WHERE target = ANY(...)`
    only stays scoped to the pack being dropped because target names are
    globally unique; that uniqueness is exactly what `all_targets()` enforces
    (it raises DuplicateTarget on a collision), so both commands must call it,
    before anything is written or destroyed, or the guarantee they rely on is
    never actually checked on the path that matters. Same shape as
    `_discover_packs()`: returns None on failure so a caller can just check
    for that and return 1.
    """
    try:
        return all_targets(packs)
    except (DuplicatePack, DuplicateTarget) as exc:
        print(str(exc), file=sys.stderr)
        return None


def _explain_unregistered(name: str, packs: Mapping[str, Pack]) -> str:
    """Why `name` did not come back from discover(): unknown, or dropped for a
    core-version mismatch.

    discover() silently skips an incompatible pack -- deliberately, so one
    third-party pack's version skew cannot take every other pack's listing
    down with it -- and that silence is exactly what would make "unknown
    pack" a misleading message here. This re-scans entry points, the same
    ones discover() itself sees, purely to explain an absence; it changes
    nothing, and callers only reach it once discover() has already failed to
    find the pack.

    `packs` is only used for the plain "unknown pack" case, to list what IS
    registered -- the same "available: ..." convention
    `registry.UnknownSource` already uses, so a typo's error message actually
    helps rather than just naming what was typed.
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
    available = ", ".join(sorted(packs)) or "-"
    return f"unknown pack: {name!r}; available: {available}"


def _require_dsn() -> str | None:
    dsn = os.environ.get("SECOPS_DB_DSN")
    if not dsn:
        print("SECOPS_DB_DSN is not set", file=sys.stderr)
        return None
    return dsn


def _load_pack_states(
    packs: dict[str, Pack],
) -> tuple[dict[str, PackState], str | None, set[str]]:
    """What the warehouse thinks, or why it cannot say.

    Returns (states, unknown_reason, extra). `unknown_reason` is None only
    when a real, queried `control.pack` is behind `states` -- callers use its
    presence to decide whether per-pack state lines mean anything at all.
    `extra` is every name in `states` that is not a currently registered
    pack: a row with no pack behind it, the "enabled but not installed" case.

    No `SECOPS_DB_DSN` and no `psycopg` are both reported as "no database":
    in either case there is nothing to connect to at all. A failure to
    connect and a failure to read, once a connection exists, are kept
    separate on purpose -- they point an operator at different fixes (the
    DSN/network/host versus a grant on `control.pack`), and collapsing the
    two into one label is exactly the kind of message that names the wrong
    thing. Every path here still exits 0 and still lets the caller print the
    packs: `list` is a diagnostic and must never fail because the thing it is
    diagnosing is broken.
    """
    dsn = os.environ.get("SECOPS_DB_DSN")
    if not dsn:
        return {}, "no database", set()

    try:
        import psycopg
    except ImportError:
        return {}, "no database", set()

    from . import state as pack_state

    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        return {}, f"could not connect: {exc}", set()

    try:
        with conn:
            states = pack_state.all_states(conn)
    except psycopg.Error as exc:
        return {}, f"connected, but could not read pack state: {exc}", set()

    return states, None, set(states) - set(packs)


def _state_marker(state: PackState | None) -> str:
    """One glanceable token per state -- not just a word, a shape too."""
    if state is None:
        return "[ ] not enabled"
    if state.state == "ENABLED":
        return "[+] ENABLED"
    return "[-] DISABLED"


def _cmd_list() -> int:
    packs = _discover_packs()
    if packs is None:
        return 1
    targets = _discover_targets(packs)
    if targets is None:
        return 1

    states, unknown_reason, extra = _load_pack_states(packs)

    for name in sorted(packs):
        pack = packs[name]
        # Safe to compare Target objects by value: all_targets() enforces
        # global uniqueness of target.name across packs before this runs.
        owned = sorted(t for t, target in targets.items() if target in pack.targets)
        print(f"{name}  {pack.version}  (core {pack.requires_core})")
        print(f"    sources: {', '.join(sorted(pack.sources)) or '-'}")
        print(f"    targets: {', '.join(owned) or '-'}")
        if unknown_reason is None:
            print(f"    state: {_state_marker(states.get(name))}")

    if unknown_reason is not None:
        print(f"state: unknown ({unknown_reason})")
    elif extra:
        print()
        print("control.pack rows with no matching installed pack (enabled but not installed):")
        for name in sorted(extra):
            row = states[name]
            print(f"    [!] {name}  {row.version}  {row.state}  -- not installed")
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
    # A target-name collision between two OTHER installed packs must refuse
    # here too, not just in `list`: the DDL this command is about to apply is
    # keyed by target name, same as `drop`'s deletes are, and the uniqueness
    # it relies on is worth nothing if only `list` ever checks it.
    if _discover_targets(packs) is None:
        return 1
    pack = packs.get(name)
    if pack is None:
        print(_explain_unregistered(name, packs), file=sys.stderr)
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

    # Connect and operate are reported as separate failures, same distinction
    # `list` already makes in `_load_pack_states`: a DSN/network/host problem
    # points an operator somewhere different than a DDL or GRANT problem does,
    # and collapsing both into one message names the wrong thing.
    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        print(f"could not connect to enable pack {name!r}: {exc}", file=sys.stderr)
        return 1

    try:
        pack_state.apply_ddl(conn, control_sql())
        pack_state.apply_ddl(conn, target_ddl)
        pack_state.set_state(conn, name, pack.version, "ENABLED")
    except psycopg.Error as exc:
        print(f"connected, but could not enable pack {name!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
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

    # Same connect/operate split as `enable` and `list` -- see the comment in
    # `_cmd_enable`.
    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        print(f"could not connect to disable pack {name!r}: {exc}", file=sys.stderr)
        return 1

    try:
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
            print(_explain_unregistered(name, packs), file=sys.stderr)
            return 1
        # Unregistered but has history (e.g. the pack was uninstalled):
        # disable it without guessing at a version it no longer declares.
        pack_state.set_state(conn, name, existing.version, "DISABLED")
    except psycopg.Error as exc:
        print(f"connected, but could not disable pack {name!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def _pack_tables(pack: Pack) -> list[str]:
    """Every table `drop` would touch for `pack`, in creation order, deduplicated.

    From the pack's targets: each raw_table, each fact_table, and each
    rollup_table that is set (rollup_table is optional per target).
    """
    tables: list[str] = []
    seen: set[str] = set()
    for target in pack.targets:
        for table in (target.raw_table, target.fact_table, target.rollup_table):
            if table and table not in seen:
                seen.add(table)
                tables.append(table)
    return tables


def _qualified_ident(qualified: str) -> sql.Identifier:
    """Turn 'schema.table' or a bare 'table' into a validated, quoted Identifier.

    raw_table is schema-qualified; fact_table and rollup_table are not -- they
    resolve against the connection's search_path, same as the DDL that created
    them (see schema.ddl_for_targets). Every component goes through
    validate_identifier before it ever reaches psycopg.sql.Identifier: these
    names arrive from a pack, which is not the same as trusted.
    """
    from psycopg import sql

    parts = qualified.split(".")
    for part in parts:
        validate_identifier(part)
    return sql.Identifier(*parts)


def _row_count(conn: psycopg.Connection, qualified: str) -> int:
    """Current row count for `qualified`, or 0 if the table does not exist.

    A table that was never created (e.g. `enable` never ran, or a prior
    `drop` already removed it) is not an error here -- there is simply
    nothing in it, and that is exactly what the inventory should say.
    """
    import psycopg
    from psycopg import sql

    ident = _qualified_ident(qualified)

    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT count(*) FROM {}").format(ident))
            row = cur.fetchone()
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return 0
    return int(row[0]) if row is not None else 0


def _print_inventory(
    name: str, tables: list[str], counts: dict[str, int], *, destroying: bool
) -> None:
    """Print every table `drop` would touch for `name`, with its row count.

    `destroying` picks the header's verb -- "destroying" once
    `--yes-destroy-data` was given and this is really about to happen,
    "would destroy" when it is not and this is a refusal. Byte-identical
    stdout between those two cases is exactly the bug this guards against: a
    converge log or 3am scrollback must be able to tell "refused, touched
    nothing" apart from "destroyed all of this" from the text alone.
    """
    verb = "destroying" if destroying else "would destroy"
    print(f"{verb} the data for pack {name!r}:")
    total = 0
    for table in tables:
        count = counts[table]
        total += count
        print(f"{table}: {count} row(s)")
    print(f"total: {total} row(s)")


def _colliding_source(
    name: str, pack: Pack, packs: Mapping[str, Pack]
) -> tuple[str, str] | None:
    """First (source_name, other_pack_name) where some OTHER registered pack
    also provides one of `pack`'s source names, or None.

    Two packs sharing a bare source name is legal -- `enable` never refuses
    it, and an operator-typed reference is disambiguated by qualification in
    `registry.resolve_source` -- but `control.ingest_watermark.source` and
    `control.ingest_run.source` store only the BARE name. `drop`'s deletes
    are scoped `WHERE source = ANY(...)` against that bare name, so on a
    collision it cannot tell which pack's rows it is about to remove. The
    real fix is storing qualified source names in those tables, a schema
    change out of scope for this wave; this is the fail-closed guard until
    that lands. `_discover_targets()`'s uniqueness check does not cover this
    -- it only enforces TARGET names, and this is about SOURCE names, which
    the design deliberately leaves free to collide at enable time.
    """
    for source_name in pack.sources:
        for other_name in sorted(packs):
            if other_name == name:
                continue
            if source_name in packs[other_name].sources:
                return source_name, other_name
    return None


def _cmd_drop(name: str, yes_destroy_data: bool) -> int:
    # Resolved from the registry first, exactly like `enable`: an unknown pack
    # is a naming problem, not a database problem, and must fail as one before
    # any connection is opened. It also means `drop` can only ever destroy
    # tables it can still name -- an uninstalled pack whose Target definitions
    # are gone cannot be dropped by name, only disabled.
    packs = _discover_packs()
    if packs is None:
        return 1
    # Checked before anything is written or destroyed: this command's control
    # deletes below are scoped `WHERE target = ANY(...)` by name, and that
    # scoping is only actually safe if no two installed packs can share a
    # target name. all_targets() is what enforces that; without calling it
    # here, two colliding packs could both be enabled and `drop` on one would
    # delete the OTHER's transform_run/transform_watermark/transform_coverage
    # rows right along with it.
    if _discover_targets(packs) is None:
        return 1
    pack = packs.get(name)
    if pack is None:
        print(_explain_unregistered(name, packs), file=sys.stderr)
        print(
            f"note: a pack that is enabled but not installed has no Target or "
            f"Source definitions left here to know what to remove -- "
            f"`disable {name}` instead; only a currently installed pack can be "
            "dropped by name.",
            file=sys.stderr,
        )
        return 1

    # Source-name collision against another registered pack: refuse before
    # anything is destroyed. Pure registry data, same as the target-name
    # check above, so this too is checked before a connection is ever opened.
    collision = _colliding_source(name, pack, packs)
    if collision is not None:
        source_name, other_name = collision
        print(
            f"pack {name!r}: source {source_name!r} is also provided by pack "
            f"{other_name!r}; refusing to drop -- control.ingest_watermark and "
            f"control.ingest_run key rows by the bare source name only, so "
            f"{name!r}'s bookkeeping for {source_name!r} cannot be told apart "
            f"from {other_name!r}'s. Nothing was destroyed.",
            file=sys.stderr,
        )
        return 1

    dsn = _require_dsn()
    if dsn is None:
        return 1

    tables = _pack_tables(pack)
    sources = list(pack.sources)
    targets = [t.name for t in pack.targets]

    import psycopg
    from psycopg import sql

    from . import state as pack_state

    # Connect and operate are reported as separate failures -- see the
    # comment in `_cmd_enable`.
    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        print(f"could not connect to drop pack {name!r}: {exc}", file=sys.stderr)
        return 1

    try:
        # `drop` requires the pack to already be DISABLED. A still-ENABLED
        # pack has a timer that may run at any moment; dropping its tables
        # out from under that timer, or racing a run already in flight, is
        # exactly what `disable` exists to prevent first. No row at all is
        # refused the same way: `run._pack_state_of` treats a missing row as
        # PROCEED (deliberately, for warehouses from before pack state
        # existed), so a pack that was never enabled/disabled has the same
        # "nothing is stopping a connector from running" problem.
        state = pack_state.get_state(conn, name)
        if state is None or state.state != "DISABLED":
            current = "has no recorded state" if state is None else f"is {state.state}"
            print(
                f"pack {name!r} {current} in this warehouse; refusing to drop "
                f"-- run `disable {name}` first. A running connector must be "
                "stopped before its data is removed, which also closes the "
                "window where a run in flight could race this drop.",
                file=sys.stderr,
            )
            return 1

        # The inventory is printed unconditionally, whether or not the flag
        # was given, so a converge log always shows what would be (or was)
        # destroyed and how much was in it -- and its header now says which
        # of those two happened, since identical stdout either way is exactly
        # what made a refusal indistinguishable from a real destruction.
        counts = {table: _row_count(conn, table) for table in tables}
        _print_inventory(name, tables, counts, destroying=yes_destroy_data)

        if not yes_destroy_data:
            print(
                "refusing: pass --yes-destroy-data to actually destroy this data.",
            )
            return 1

        # Bookkeeping is deleted FIRST, tables dropped second -- the inverse
        # of `_cmd_enable`'s ordering (see the "written strictly last" comment
        # there): there, the control row must never claim more than the DDL
        # actually applied; here, the control rows must never claim a cursor
        # or a covered period for a table that no longer exists. A crash
        # between these two steps leaves a state that is trivial to finish --
        # re-run `drop`, or run `enable` again, both idempotent -- but the
        # reverse (tables gone, bookkeeping intact) is not recoverable: raw is
        # a bounded re-derivation buffer (ADR-0002), a resumed worker would
        # trust the stale watermark and never re-fetch the gap, and
        # transform_coverage would keep raw expiry armed for periods whose
        # facts no longer exist.
        with conn.cursor() as cur:
            if sources:
                cur.execute(
                    "DELETE FROM control.ingest_watermark WHERE source = ANY(%s)",
                    (sources,),
                )
                cur.execute(
                    "DELETE FROM control.ingest_run WHERE source = ANY(%s)",
                    (sources,),
                )
            if targets:
                cur.execute(
                    "DELETE FROM control.transform_watermark WHERE target = ANY(%s)",
                    (targets,),
                )
                cur.execute(
                    "DELETE FROM control.transform_run WHERE target = ANY(%s)",
                    (targets,),
                )
                # transform_coverage is the ledger that makes dropping a raw
                # partition safe elsewhere; it is keyed by target. Target
                # names are enforced globally unique across every installed
                # pack at both enable and drop time -- see the
                # _discover_targets() call above, which refuses to run
                # this command at all on a collision -- so deleting this
                # pack's own rows re-arms the guard only for targets this
                # pack owns -- whose raw tables are about to be dropped below,
                # so there is nothing left for the guard to protect -- and
                # cannot touch another pack's rows, because no other
                # installed pack's target is allowed to share these names.
                cur.execute(
                    "DELETE FROM control.transform_coverage WHERE target = ANY(%s)",
                    (targets,),
                )
        conn.commit()

        # DROP TABLE IF EXISTS, never CASCADE: a partitioned table's
        # partitions go with it, but anything else depending on these
        # tables must fail loudly rather than be destroyed silently.
        for table in tables:
            ident = _qualified_ident(table)
            with conn.cursor() as cur:
                cur.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(ident))
        conn.commit()

        # The control.pack row is left in place, still DISABLED (checked
        # above, and nothing here touches control.pack) rather than deleted.
        # Deleting it would hand back exactly the property `disable` exists
        # to remove: `run._pack_state_of` treats no row at all as PROCEED, so
        # a surviving timer for a dropped pack would stop refusing and run
        # for real against tables that no longer exist.
        print(f"destroyed the data for pack {name!r}.")
    except psycopg.Error as exc:
        print(f"connected, but could not drop pack {name!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.packs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="show every pack this install can see")
    enable_parser = subparsers.add_parser("enable", help="enable a pack in the warehouse")
    enable_parser.add_argument("name")
    disable_parser = subparsers.add_parser("disable", help="disable a pack in the warehouse")
    disable_parser.add_argument("name")
    drop_parser = subparsers.add_parser(
        "drop", help="destroy a pack's tables and control rows in the warehouse"
    )
    drop_parser.add_argument("name")
    drop_parser.add_argument(
        "--yes-destroy-data",
        action="store_true",
        help="actually drop the tables listed in the inventory; without this, nothing is destroyed",
    )
    args = parser.parse_args(argv)

    _configure_logging()

    if args.command == "list":
        return _cmd_list()
    if args.command == "enable":
        return _cmd_enable(args.name)
    if args.command == "disable":
        return _cmd_disable(args.name)
    return _cmd_drop(args.name, args.yes_destroy_data)


if __name__ == "__main__":
    sys.exit(main())
