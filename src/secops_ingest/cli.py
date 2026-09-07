"""Command line entry point.

    python -m secops_ingest <source> [--dry-run]

Scheduling is deliberately external. systemd timers are what this project uses,
but the CLI is the interface, so cron or a Kubernetes CronJob work unchanged.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys
from typing import Any

from .redaction import RedactingFilter


def _load_source(name: str) -> Any:
    target = f"secops_ingest.sources.{name}"
    try:
        module = importlib.import_module(f".sources.{name}", package="secops_ingest")
    except ModuleNotFoundError as exc:
        # Only "the connector does not exist" should report as an unknown
        # source. An ImportError raised INSIDE the connector (a typo, a missing
        # optional dependency) must surface as itself, or it sends someone to
        # debug the module name instead of the real cause.
        if exc.name == target:
            raise SystemExit(f"unknown source: {name}") from exc
        raise
    if not hasattr(module, "SOURCE"):
        raise SystemExit(f"source module {name} does not define SOURCE")
    return module.SOURCE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest")
    parser.add_argument("source", help="connector name, e.g. phisher")
    parser.add_argument("--dry-run", action="store_true",
                        help="fetch and validate, write nothing")
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.batch_size is not None and args.batch_size < 1:
        parser.error("--batch-size must be >= 1")

    redactor = RedactingFilter()
    handler = logging.StreamHandler()
    handler.addFilter(redactor)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
    )

    from .common import run as run_mod

    source = _load_source(args.source)
    kwargs = {"dry_run": args.dry_run}
    if args.batch_size is not None:
        kwargs["batch_size"] = args.batch_size

    log = logging.getLogger(__name__)
    try:
        result = run_mod.execute(source, **kwargs)
    except Exception:
        log.exception("source=%s failed", args.source)
        return 1
    log.info(
        "done status=%s read=%s written=%s",
        result.status, result.rows_read, result.rows_written,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
