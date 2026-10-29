"""Emit the warehouse DDL.

    python -m secops_ingest.schema | psql "$DSN"
    python -m secops_ingest.schema --target wazuh_alerts --partitions-ahead 6
    python -m secops_ingest.schema --all-targets --all-sources --partitions-only
    python -m secops_ingest.schema --all-targets --all-sources --table-map

Writes SQL to stdout and never connects to a database. Review it, pipe it, or
hand it to whatever applies migrations here -- the point is that the schema is
readable and portable rather than locked inside one deployment tool.

Everything is derived from the transform targets, which already know their raw
table, their fact table and how to create both. Connector modules are not
imported, so this works with no optional dependency installed -- unless
`--all-sources` asks for every connector's raw table, which only the connector
itself declares.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys
from typing import Any

from ..packs.model import Pack
from ..packs.registry import DuplicatePack, DuplicateTarget, all_targets, discover
from ..redaction import RedactingFilter
from . import (
    control_sql,
    ddl_for_targets,
    grants_sql,
    mart_partition_sql,
    partition_check_sql,
    partition_health_sql,
    partitions_sql,
    raw_table_sql,
    source_freshness_sql,
    source_state_sql,
)


def _banner(text: str) -> str:
    return f"\n-- {'=' * 72}\n-- {text}\n-- {'=' * 72}\n"


def _source_tables(packs: dict[str, Pack]) -> tuple[dict[str, str], list[str]]:
    """{source name: raw table} for every registered source, and what failed.

    THE TABLE IS DECLARED ONLY BY THE CONNECTOR, so this imports every one of
    them. That is why it is behind a flag: a connector module pulls in its
    optional dependencies (httpx, for most), and the default emitter must keep
    working without them. A connector that cannot be imported is reported by
    name rather than skipped -- a generated schema that is quietly missing one
    source's table fails that source on its first run, which is exactly the
    drift this flag exists to end.
    """
    tables: dict[str, str] = {}
    problems: list[str] = []
    for pack in packs.values():
        for source_name, ref in sorted(pack.sources.items()):
            module_path, _, attr = ref.partition(":")
            try:
                source = getattr(importlib.import_module(module_path), attr)
            except ImportError as exc:
                extras = f" (pack extras: {', '.join(pack.extras)})" if pack.extras else ""
                problems.append(
                    f"source {pack.name}.{source_name}: cannot import {module_path}: "
                    f"{exc}{extras}"
                )
                continue
            except AttributeError:
                problems.append(f"source {pack.name}.{source_name}: {module_path} has no {attr}")
                continue
            table = getattr(source, "table", None)
            if not isinstance(table, str) or not table.partition(".")[2]:
                problems.append(
                    f"source {pack.name}.{source_name}: table {table!r} is not SCHEMA.TABLE"
                )
                continue
            tables[source_name] = table
    return tables, problems


def _freshness_sources(
    packs: dict[str, Pack], names: list[str], targets: dict[str, Any],
    source_tables: dict[str, str],
) -> list[tuple[str, str | None, list[str]]]:
    """(source, pack, targets reading its raw table) for control.source_freshness.

    Only the targets being emitted count. A deployment that emits a subset does
    not run the others, and a target that never runs would hold its source's
    freshness at "never" for good.
    """
    out: list[tuple[str, str | None, list[str]]] = []
    seen: set[str] = set()
    for pack_name in sorted(packs):
        for source_name in sorted(packs[pack_name].sources):
            # Two packs may share a bare source name; the run ledger cannot
            # tell them apart either, so the first pack in name order speaks.
            if source_name in seen:
                continue
            seen.add(source_name)
            table = source_tables.get(source_name)
            reading = [n for n in names if targets[n].raw_table == table]
            out.append((source_name, pack_name, reading))
    return out


def _parse_remote(specs: list[str], parser: argparse.ArgumentParser) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for spec in specs:
        role, sep, schema = spec.partition(":")
        if not sep or not role or not schema:
            parser.error(f"--remote-ingest-role expects ROLE:RAW_SCHEMA, got {spec!r}")
        out.append((role, schema))
    return out


def main(argv: list[str] | None = None) -> int:
    # Installed before any registry call: all_targets() below walks every
    # installed pack, and a pack that raises on load is logged by registry.py
    # through this handler -- an import error can embed a secret as easily as
    # a connector's own logging can.
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
    )

    parser = argparse.ArgumentParser(prog="secops_ingest.schema")
    parser.add_argument(
        "--target", action="append", metavar="NAME",
        help="target to emit DDL for; repeatable. Default: all, unless --raw is given.",
    )
    # --raw alone means "just these tables", so a deployment that wants every
    # target AND some extra raw tables needs a way to say so without listing the
    # targets by hand -- a hand list is what drifted from the package before.
    parser.add_argument(
        "--all-targets", action="store_true",
        help="every registered target, in registration order, even with --raw.",
    )
    # A deployment can land sources that have no transform target yet -- or whose
    # connector lives in a private repository. Without this the emitter could
    # only describe schemas it already knew about, which is not much use to
    # anyone whose sources differ from the examples.
    parser.add_argument(
        "--raw", action="append", metavar="SCHEMA.TABLE",
        help="extra raw landing table with no target; repeatable.",
    )
    parser.add_argument(
        "--all-sources", action="store_true",
        help="also every registered source's raw table, whether or not a target "
             "reads it. Imports every connector, so needs their extras installed.",
    )
    parser.add_argument("--partitions-behind", type=int, default=1)
    parser.add_argument("--partitions-ahead", type=int, default=3)
    # The window only moves when this runs. Emitted on a deploy alone, it is a
    # promise that lapses after `ahead` quiet months; this mode is what a timer
    # runs, so the lookahead is maintained rather than assumed.
    parser.add_argument(
        "--partitions-only", action="store_true",
        help="emit only the idempotent partition blocks, then a check that fails "
             "unless next month exists for every parent. For a partition timer: "
             "no control, no CREATE TABLE, no grants.",
    )
    parser.add_argument(
        "--table-map", action="store_true",
        help="print a JSON map of targets, raw tables and (with --all-sources) "
             "sources instead of SQL.",
    )
    parser.add_argument(
        "--gin", action="store_true",
        help="index raw JSONB payloads. Write-amplifying; only worth it if raw "
             "is queried ad hoc.",
    )
    parser.add_argument(
        "--no-control", action="store_true", help="skip the control schema"
    )
    # Role names are a local convention, so nothing is granted unless asked for.
    parser.add_argument("--ingest-role", metavar="ROLE",
                        help="role that lands raw records; grants emitted if given")
    parser.add_argument("--transform-role", metavar="ROLE",
                        help="role that derives the mart layer")
    parser.add_argument("--read-role", metavar="ROLE",
                        help="reporting role (Metabase, Grafana, ...): mart and "
                             "read-only control")
    parser.add_argument("--monitor-role", metavar="ROLE",
                        help="external monitoring role: read-only control and "
                             "partition health, nothing else")
    parser.add_argument(
        "--remote-ingest-role", action="append", metavar="ROLE:RAW_SCHEMA", default=[],
        help="a writer confined to one raw schema, e.g. for a worker on another "
             "host; the --ingest-role loses that schema. Repeatable.",
    )
    # Escape hatch, not a mode: confining a schema to a remote writer revokes it
    # from the shared role, and a remote host still using the shared credential
    # would go dark at that moment. This lets the new role exist first.
    parser.add_argument(
        "--shared-ingest-keeps-remote", action="store_true",
        help="TRANSITIONAL: the --ingest-role keeps the --remote-ingest-role "
             "schemas too, until the remote host has switched credentials",
    )
    parser.add_argument(
        "--owner-role", metavar="ROLE",
        help="role that owns and creates raw tables, so default privileges cover "
             "tables it creates, not only ones created by whoever applies this file",
    )
    args = parser.parse_args(argv)
    remote = _parse_remote(args.remote_ingest_role, parser)
    if args.shared_ingest_keeps_remote:
        if not remote or not args.ingest_role:
            parser.error("--shared-ingest-keeps-remote needs --ingest-role and "
                         "--remote-ingest-role")
        logging.getLogger(__name__).warning(
            "--shared-ingest-keeps-remote: %s keeps write access to %s; the remote "
            "writer is not yet confined. Drop the flag once the remote host has "
            "switched credentials.",
            args.ingest_role, ", ".join(schema for _role, schema in remote),
        )
    if args.partitions_only and args.table_map:
        parser.error("--partitions-only and --table-map are different outputs; pick one")

    try:
        packs = discover()
        targets = all_targets(packs)
    except (DuplicatePack, DuplicateTarget) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # --raw alone means "just these tables"; naming targets as well brings both.
    # Registration order, not sorted: a target may read another's mart table
    # (incident_lifecycle reads xdr_incidents'), and TARGETS is declared in the
    # order that DDL has to run.
    if args.all_targets:
        names = list(targets) + [n for n in args.target or [] if n not in targets]
    elif args.target:
        names = args.target
    else:
        names = [] if (args.raw or args.all_sources) else list(targets)
    unknown = [n for n in names if n not in targets]
    if unknown:
        parser.error(
            f"unknown target(s): {', '.join(unknown)}. Known: {', '.join(sorted(targets))}"
        )
    names = list(dict.fromkeys(names))

    for name in names:
        if not targets[name].raw_table.partition(".")[2]:
            print(f"target {name}: raw_table {targets[name].raw_table!r} is not "
                  "schema-qualified", file=sys.stderr)
            return 1

    source_tables: dict[str, str] = {}
    if args.all_sources:
        source_tables, problems = _source_tables(packs)
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1

    # Every raw table with no target among `names`, once each, in a stable order:
    # --raw as given, then sources' tables. A table a target already creates is
    # not repeated -- it would be harmless SQL, but it would make a review of the
    # generated file ask why one table appears twice.
    covered = {targets[n].raw_table for n in names}
    extra_raw: list[tuple[str, str, str]] = []
    for spec in args.raw or []:
        schema, _, table = spec.partition(".")
        if not schema or not table:
            parser.error(f"--raw expects SCHEMA.TABLE, got {spec!r}")
        if spec not in covered:
            covered.add(spec)
            extra_raw.append((schema, table, "raw only, no transform target"))
    for source_name, qualified in sorted(source_tables.items(), key=lambda kv: kv[1]):
        if qualified not in covered:
            covered.add(qualified)
            schema, _, table = qualified.partition(".")
            extra_raw.append((schema, table, f"raw only, written by source {source_name}"))

    if args.table_map:
        return _print_table_map(names, targets, extra_raw, source_tables, args.all_sources)

    if args.partitions_only:
        return _print_partitions_only(names, targets, extra_raw, args)

    out: list[str] = [
        "-- Generated by `python -m secops_ingest.schema`. Idempotent: every",
        "-- statement is IF NOT EXISTS or a guarded DO block, so re-running is safe.",
    ]

    if not args.no_control:
        out.append(_banner("control — run history, watermarks, coverage ledger"))
        out.append(control_sql())
        out.append(partition_health_sql())
        out.append(source_state_sql())
        # The view maps each source to the targets that read its raw table, and
        # only the connector declares that table -- so it needs --all-sources,
        # like the raw tables themselves. Without it the view is left out
        # rather than emitted with every source claiming it has no target,
        # which would report a frozen mart as current.
        if args.all_sources:
            out.append(source_freshness_sql(
                _freshness_sources(packs, names, targets, source_tables)))
        else:
            out.append("-- control.source_freshness is emitted only with --all-sources: "
                       "it maps each\n-- source to the targets reading its raw table, "
                       "which only the connector declares.\n")

    for schema, table, why in extra_raw:
        out.append(_banner(f"{schema}.{table} ({why})"))
        out.append(raw_table_sql(schema, table, gin_index=args.gin))
        out.append(
            f"-- monthly partitions for {schema}.{table}\n"
            + partitions_sql(schema, table,
                             behind=args.partitions_behind, ahead=args.partitions_ahead)
        )

    for name in names:
        out.append(_banner(f"{name}"))
        out.append(
            ddl_for_targets(
                [targets[name]],
                behind=args.partitions_behind,
                ahead=args.partitions_ahead,
                gin_index=args.gin,
            )
        )

    # Grants come last, once every object they name exists. GRANT ... ON ALL
    # TABLES IN SCHEMA is evaluated at execution time, so emitting it earlier
    # would silently skip tables created further down the file.
    if args.ingest_role or args.transform_role or args.read_role or args.monitor_role or remote:
        raw_schemas: list[str] = []
        mart_tables: list[str] = []
        for schema, _table, _why in extra_raw:
            if schema not in raw_schemas:
                raw_schemas.append(schema)
        for name in names:
            t = targets[name]
            schema = t.raw_table.partition(".")[0]
            if schema not in raw_schemas:
                raw_schemas.append(schema)
            if t.fact_ddl:
                mart_tables.append(t.fact_table)
            if t.rollup_ddl and t.rollup_table:
                mart_tables.append(t.rollup_table)
        out.append(_banner("privileges"))
        try:
            out.append(
                grants_sql(
                    raw_schemas, mart_tables,
                    ingest_role=args.ingest_role,
                    transform_role=args.transform_role,
                    read_role=args.read_role,
                    monitor_role=args.monitor_role,
                    remote_ingest=remote,
                    owner_role=args.owner_role,
                    partition_health=not args.no_control,
                    source_state=not args.no_control,
                    shared_keeps_remote=args.shared_ingest_keeps_remote,
                )
            )
        except ValueError as exc:
            parser.error(str(exc))

    print("\n".join(out))
    return 0


def _print_partitions_only(
    names: list[str], targets: dict[str, Any], extra_raw: list[tuple[str, str, str]],
    args: argparse.Namespace,
) -> int:
    """Just the partition blocks, for a timer, and the check that judges them.

    Grants are deliberately not part of this output even when roles are named.
    Access goes through the parent table, whose grants a new partition does not
    change, so re-granting buys nothing here -- and the REVOKE half of the
    grants is a statement a timer has no business running unattended.
    """
    out: list[str] = [
        "-- Generated by `python -m secops_ingest.schema --partitions-only`.",
        "-- Idempotent; run from a timer with psql -v ON_ERROR_STOP=1 so the final",
        "-- check's failure is the unit's failure.",
    ]
    parents: list[tuple[str | None, str]] = []
    for schema, table, _why in extra_raw:
        out.append(f"-- {schema}.{table}\n"
                   + partitions_sql(schema, table, behind=args.partitions_behind,
                                    ahead=args.partitions_ahead))
        parents.append((schema, table))
    for name in names:
        t = targets[name]
        schema, _, table = t.raw_table.partition(".")
        if (schema, table) not in parents:
            out.append(f"-- {t.raw_table}\n"
                       + partitions_sql(schema, table, behind=args.partitions_behind,
                                        ahead=args.partitions_ahead))
            parents.append((schema, table))
        if t.fact_ddl and "PARTITION BY RANGE" in t.fact_ddl:
            out.append(f"-- {t.fact_table}\n"
                       + mart_partition_sql(t.fact_table, behind=args.partitions_behind,
                                            ahead=args.partitions_ahead))
            parents.append((None, t.fact_table))
    out.append("-- every parent must reach next month, or this run failed")
    out.append(partition_check_sql(parents))
    print("\n".join(out))
    return 0


def _print_table_map(
    names: list[str], targets: dict[str, Any], extra_raw: list[tuple[str, str, str]],
    source_tables: dict[str, str], with_sources: bool,
) -> int:
    """JSON: what each target reads and writes, and who reads each raw table.

    `raw_tables` is the half a raw-expiry gate needs. Two targets can read the
    same raw table (xsoar_incidents and incident_lifecycle both read
    raw_xsoar.incidents), and a gate that checks coverage for only one of them
    can authorise dropping rows the other never derived. A raw table with an
    empty list has no target at all: nothing reports it, so nothing can prove a
    partition of it safe to drop.
    """
    raw_tables: dict[str, list[str]] = {}
    for name in names:
        raw_tables.setdefault(targets[name].raw_table, []).append(name)
    for schema, table, _why in extra_raw:
        raw_tables.setdefault(f"{schema}.{table}", [])
    doc: dict[str, Any] = {
        "targets": {
            name: {
                "raw_table": targets[name].raw_table,
                "fact_table": targets[name].fact_table,
                "rollup_table": targets[name].rollup_table,
            }
            for name in names
        },
        "raw_tables": raw_tables,
    }
    if with_sources:
        doc["sources"] = dict(sorted(source_tables.items()))
    print(json.dumps(doc, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
