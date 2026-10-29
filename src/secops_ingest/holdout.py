"""python -m secops_ingest.holdout {sync,hold,release,list}

Records in the warehouse that the deployment holds a source out, and why
(audit V-18). A source the deployment does not schedule -- the secops_ingest
role's `ingest_disabled_sources` -- used to leave no trace at all: no timer, no
run, no ledger row, and a freshness card that could not tell "held out on
purpose" from "broken". This writes a `control.source_state` row (origin
'deploy') instead, which `control.source_freshness` shows beside the run
ledgers.

    python -m secops_ingest.holdout sync xdr_alerts ksat --reason "ingest_disabled_sources"
    python -m secops_ingest.holdout sync --reason unused   # releases every hold-out of mine
    python -m secops_ingest.holdout hold xdr_alerts --reason "vendor API broken, INC-1234"
    python -m secops_ingest.holdout release xdr_alerts
    python -m secops_ingest.holdout list

`sync` is what a converge runs: it holds out exactly the sources named and
releases this login's other hold-outs, so removing a source from the list is
what clears it. Hold-outs recorded by another login are never touched; see
control.release_source().

`--managed` SCOPES THE RELEASE, and a deployment should always pass it. Two
hosts may converge with the same login (the enclave defaults to wh_ingest too),
and without a scope the host that holds nothing would release the other host's
hold-out on every converge, and the other would put it back: a ledger that
flaps and is wrong for whichever ran last. With `--managed`, only sources in
that list -- the ones this host schedules or holds out -- are ever released,
and every source held out must be in it:

    python -m secops_ingest.holdout sync xdr_alerts --managed wazuh xdr xdr_alerts \
        --reason "listed in ingest_disabled_sources"

WHICH DSN. The worker's own, from the same environment as the ingest units
(SECOPS_DB_DSN, or a lease through SECOPS_SECRETS_BACKEND), not the schema
owner's: the ingest role may write control.source_state only through the two
SECURITY DEFINER functions the generated schema grants it, which can touch
nothing but the deployment's own rows. It could not clear a pack's DISABLED row
if it tried.

EXIT CODES, for the caller to tell dim from broken:
    0  done; the last line of stdout is `changed: true` or `changed: false`
    3  the warehouse predates control.source_state or its functions: nothing
       was recorded, and the remedy is printed. A converge should report this
       as running dim, not fail -- the sources are still held out by not being
       scheduled; only the trace is missing.
    1  anything else (no DSN, cannot connect, a refused release, a bad name)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .redaction import RedactingFilter

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the import lazy
    import psycopg

log = logging.getLogger(__name__)

#: The exit code for "this warehouse cannot record hold-outs yet".
EXIT_DIM = 3

#: Shown with EXIT_DIM. The functions come from the generated schema, applied
#: by the warehouse converge as the owner; nothing a worker can run fixes it.
REMEDY = (
    "apply the generated warehouse schema (python -m secops_ingest.schema "
    "--all-targets --all-sources ...) as the schema owner, then re-run this"
)

_MAX_REASON = 500


class NotRecordable(RuntimeError):
    """The warehouse has no control.source_state or hold-out functions yet."""


def _registered_sources() -> set[str] | None:
    """Every source name the installed packs declare, or None if unknown.

    Only used to warn about a name nobody declares -- a typo in the hold-out
    list would otherwise record a row for a source that does not exist, while
    the real one keeps running. Recorded anyway, since a private pack's source
    may legitimately be unknown to this install.
    """
    from .packs.registry import DuplicatePack, DuplicateTarget, discover

    try:
        packs = discover()
    except (DuplicatePack, DuplicateTarget):
        return None
    return {name for pack in packs.values() for name in pack.sources}


def _check_names(sources: Sequence[str], *, warn: bool = True) -> list[str]:
    """Validated, deduplicated names, in the order given. Raises ValueError.

    `warn` names any source no installed pack declares; off for --managed,
    whose held-out members are already checked as SOURCEs.
    """
    from .schema import validate_identifier

    out: list[str] = []
    for name in sources:
        validate_identifier(name)
        if name not in out:
            out.append(name)
    known = _registered_sources() if warn else None
    if known is not None:
        for name in out:
            if name not in known:
                print(f"[!] {name}: no installed pack declares this source; "
                      "recorded anyway (check the spelling)", file=sys.stderr)
    return out


def _is_missing_object(exc: Exception) -> bool:
    import psycopg

    return isinstance(exc, (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedFunction))


def _call(conn: psycopg.Connection, statement: str, params: tuple[Any, ...]) -> Any:
    """One function call; a missing table or function becomes NotRecordable."""
    import psycopg

    try:
        with conn.cursor() as cur:
            cur.execute(statement, params)
            row = cur.fetchone()
    except psycopg.Error as exc:
        conn.rollback()
        if _is_missing_object(exc):
            raise NotRecordable(str(exc).strip().splitlines()[0]) from None
        raise
    return row[0] if row is not None else None


def hold(conn: psycopg.Connection, source: str, reason: str) -> bool:
    """Hold `source` out; True if that changed anything. Commits."""
    changed = bool(_call(conn, "SELECT control.hold_out_source(%s, %s)", (source, reason)))
    conn.commit()
    return changed


def release(conn: psycopg.Connection, source: str) -> bool:
    """Release a hold-out this login recorded; True if there was one. Commits."""
    changed = bool(_call(conn, "SELECT control.release_source(%s)", (source,)))
    conn.commit()
    return changed


def my_hold_outs(conn: psycopg.Connection) -> list[str]:
    """Sources this login currently holds out, by name."""
    import psycopg

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source FROM control.source_state "
                "WHERE origin = 'deploy' AND state = 'HELD_OUT' AND changed_by = session_user "
                "ORDER BY source"
            )
            rows = cur.fetchall()
    except psycopg.Error as exc:
        conn.rollback()
        if _is_missing_object(exc):
            raise NotRecordable(str(exc).strip().splitlines()[0]) from None
        raise
    return [str(r[0]) for r in rows]


def sync(
    conn: psycopg.Connection, sources: Sequence[str], reason: str,
    managed: Sequence[str] | None = None,
) -> list[str]:
    """Hold out exactly `sources` for this login; returns one line per change.

    Releases this login's other hold-outs -- only those in `managed` when it is
    given (see the module docstring for why a deployment must give it). Holds
    first, then releases: a source moving between two names in one converge is
    never briefly shown as running.
    """
    changes: list[str] = []
    for source in sources:
        if hold(conn, source, reason):
            changes.append(f"held out: {source} ({reason})")
    for source in my_hold_outs(conn):
        if source in sources or (managed is not None and source not in managed):
            continue
        if release(conn, source):
            changes.append(f"released: {source}")
    return changes


def _print_state(conn: psycopg.Connection) -> None:
    """The freshness view when it exists, else the bare state table."""
    import psycopg

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source, state, coalesce(state_reason, ''), as_of, "
                "array_to_string(never_succeeded, ',') "
                "FROM control.source_freshness ORDER BY source"
            )
            rows = cur.fetchall()
        for source, state, reason, as_of, never in rows:
            shown = as_of.isoformat(timespec="seconds") if as_of else f"never ({never})"
            print(f"{source}  {state}  as of {shown}  {reason}".rstrip())
        return
    except psycopg.Error as exc:
        conn.rollback()
        if not _is_missing_object(exc):
            raise
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source, origin, state, coalesce(reason, ''), changed_at, changed_by "
                "FROM control.source_state ORDER BY source, origin"
            )
            rows = cur.fetchall()
    except psycopg.Error as exc:
        conn.rollback()
        if _is_missing_object(exc):
            raise NotRecordable(str(exc).strip().splitlines()[0]) from None
        raise
    print("(control.source_freshness is not in this warehouse; showing control.source_state)")
    for source, origin, state, reason, changed_at, changed_by in rows:
        print(f"{source}  {origin}  {state}  {changed_at.isoformat(timespec='seconds')}  "
              f"{changed_by}  {reason}".rstrip())


def _connect() -> Any:
    """db.connect() with the worker's own secret provider, as the CLI builds it."""
    from .common import db
    from .secrets import get_provider

    provider = get_provider() if os.environ.get("SECOPS_SECRETS_BACKEND") else None
    return db.connect(provider)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.holdout")
    sub = parser.add_subparsers(dest="command", required=True)
    sync_p = sub.add_parser(
        "sync", help="hold out exactly these sources for this login; release the rest of mine"
    )
    sync_p.add_argument("sources", nargs="*", metavar="SOURCE")
    sync_p.add_argument("--reason", required=True,
                        help="why, shown on the freshness card (1-500 characters)")
    sync_p.add_argument(
        "--managed", nargs="+", metavar="SOURCE",
        help="the sources this caller manages (schedules or holds out); only these are "
             "ever released, and every SOURCE held out must be among them. Pass it "
             "whenever two hosts share a login.",
    )
    hold_p = sub.add_parser("hold", help="hold these sources out")
    hold_p.add_argument("sources", nargs="+", metavar="SOURCE")
    hold_p.add_argument("--reason", required=True,
                        help="why, shown on the freshness card (1-500 characters)")
    release_p = sub.add_parser("release", help="release hold-outs this login recorded")
    release_p.add_argument("sources", nargs="+", metavar="SOURCE")
    sub.add_parser("list", help="show every source's state and freshness")
    args = parser.parse_args(argv)

    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        handlers=[handler])

    # "" for release and list, which take no reason; argparse makes it
    # required for the two commands that record one.
    reason: str = getattr(args, "reason", None) or ""
    if args.command in ("sync", "hold") and not (
        0 < len(reason.strip()) and len(reason) <= _MAX_REASON
    ):
        parser.error(f"--reason must be 1 to {_MAX_REASON} characters")
    try:
        sources = _check_names(getattr(args, "sources", []))
        managed_arg = getattr(args, "managed", None)
        managed = None if managed_arg is None else _check_names(managed_arg, warn=False)
    except ValueError as exc:
        parser.error(str(exc))
    if managed is not None:
        # A hold-out outside the scope could never be released by this caller,
        # which is the stuck row the scope exists to avoid.
        outside = [s for s in sources if s not in managed]
        if outside:
            parser.error(f"held out but not in --managed: {', '.join(outside)}")

    try:
        import psycopg
    except ImportError:
        print("the hold-out CLI needs the 'postgres' extra: pip install "
              "secops-ingest[postgres]", file=sys.stderr)
        return 1

    try:
        with _connect() as conn:
            if args.command == "list":
                _print_state(conn)
                return 0
            if args.command == "sync":
                changes = sync(conn, sources, reason, managed)
            elif args.command == "hold":
                changes = [f"held out: {s} ({reason})" for s in sources
                           if hold(conn, s, reason)]
            else:
                changes = [f"released: {s}" for s in sources if release(conn, s)]
    except NotRecordable as exc:
        print(f"running dim: this warehouse cannot record hold-outs yet ({exc}); "
              f"nothing was recorded. To fix: {REMEDY}.", file=sys.stderr)
        return EXIT_DIM
    except psycopg.Error as exc:
        detail = (str(exc).strip().splitlines() or [type(exc).__name__])[0]
        print(f"could not {args.command} hold-outs: {detail}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        # resolve_conninfo's "SECOPS_DB_DSN is not set" and its lease refusals.
        print(f"could not {args.command} hold-outs: {exc}", file=sys.stderr)
        return 1

    for line in changes:
        print(line)
    print(f"changed: {'true' if changes else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
