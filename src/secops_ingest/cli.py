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

from .packs.registry import AmbiguousSource, DuplicatePack, UnknownSource, resolve_source
from .redaction import RedactingFilter


def _load_source(name: str) -> Any:
    """Resolve a source reference and import the connector it names.

    Two failures are kept distinct. An unregistered name is a usage error and
    exits with a message naming it. An ImportError raised INSIDE the connector
    -- a typo, a missing optional dependency -- surfaces as itself, because
    reporting it as "unknown source" sends someone to debug the module name
    instead of the real cause.

    A registry-wide failure -- a third-party pack colliding with another one --
    is also reported as a clean message rather than a traceback: it is an
    installation problem, not a bug in this process.
    """
    try:
        target = resolve_source(name)
    except (UnknownSource, AmbiguousSource, DuplicatePack) as exc:
        raise SystemExit(str(exc)) from exc

    module_path, _, attr = target.partition(":")
    module = importlib.import_module(module_path)
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise SystemExit(f"source module {module_path} does not define {attr}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest")
    parser.add_argument("source", help="connector name, e.g. wazuh or builtin.wazuh")
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
    # DISABLED is a deliberate operator choice and exits 0, same as SUCCESS, so
    # a timer firing against it never trains anyone to ignore alerts. AMBIGUOUS
    # is a misconfiguration nobody chose -- two packs collide on a bare source
    # name -- so it exits non-zero and stays noisy until someone fixes it.
    return 1 if result.status == "AMBIGUOUS" else 0


if __name__ == "__main__":
    sys.exit(main())
