"""python -m secops_ingest.transform <target>"""

from __future__ import annotations

import argparse
import logging
import sys

from ..packs.registry import DuplicatePack, DuplicateTarget, all_targets
from ..redaction import RedactingFilter


def main(argv: list[str] | None = None) -> int:
    # Installed before all_targets() runs: that call walks every installed
    # pack, and a pack that raises on load is logged by registry.py through
    # this handler -- an import error can embed a secret as easily as a
    # connector's own logging can.
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
    )
    log = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(prog="secops_ingest.transform")
    try:
        targets = all_targets()
    except (DuplicatePack, DuplicateTarget) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    parser.add_argument("target", choices=sorted(targets))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Imported here, not at module scope: runner pulls in psycopg, which is the
    # optional "postgres" extra. A module-level import meant this entry point
    # could not even be imported without a database driver, so its own test
    # skipped in every CI run -- CI installs [dev,http] and [vault,dev], never
    # postgres -- and the error handling below was never exercised anywhere.
    # Argument parsing and registry failures need no driver; only running a
    # transform does.
    from . import runner

    try:
        result = runner.execute(targets[args.target])
    except Exception:
        # Log here as well as in the runner: a bare `return 1` produced an exit
        # code with no output at all, which is indistinguishable from a crash.
        log.exception("transform target=%s failed", args.target)
        return 1
    log.info(
        "done status=%s rows=%s days=%s",
        result.status, result.rows_upserted, result.days_touched,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
