"""python -m secops_ingest.transform <target>"""

from __future__ import annotations

import argparse
import inspect
import logging
import sys

from ..packs.registry import DuplicatePack, DuplicateTarget, all_targets
from ..redaction import RedactingFilter
from .base import Target


def _runnable_targets() -> dict[str, Target]:
    """Every target this worker can run, minus any whose name two packs claim.

    A collision between two third-party packs must not take every transform
    down, built-in ones included (V-33): this entry point only RUNS targets,
    so it drops the colliding ones loudly and keeps the rest. `pack enable` and
    `drop` keep refusing outright, because they write by target name.

    MERGE WINDOW: skip_collisions lands on fix/audit-schema. On a registry
    without it this falls back to the old refuse-everything behaviour; once
    both branches are merged, call all_targets(skip_collisions=True) directly.
    """
    if "skip_collisions" in inspect.signature(all_targets).parameters:
        return all_targets(skip_collisions=True)  # type: ignore[call-arg, unused-ignore]
    return all_targets()


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
        targets = _runnable_targets()
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
    from ..common import schema_check
    from . import runner

    # A tuple, so the target check's refusal reads exactly like the control
    # one. MERGE WINDOW: TargetSchemaDrift lands on fix/audit-schema; import it
    # directly once both branches are merged.
    drift: tuple[type[Exception], ...] = tuple(
        getattr(schema_check, name)
        for name in ("ControlSchemaDrift", "TargetSchemaDrift")
        if hasattr(schema_check, name)
    )

    try:
        result = runner.execute(targets[args.target])
    except drift as exc:
        # The warehouse is older than the package: a configuration state, not
        # a crash, so one line on stderr and a non-zero exit -- never the
        # traceback the generic handler below would log.
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        # Log here as well as in the runner: a bare `return 1` produced an exit
        # code with no output at all, which is indistinguishable from a crash.
        log.exception("transform target=%s failed", args.target)
        return 1
    log.info(
        "done status=%s rows=%s days=%s",
        result.status, result.rows_upserted, result.days_touched,
    )
    # A wind-down (deadline or SIGTERM) returns rather than raises, with FAILED
    # already in the ledger; the exit code has to agree with it, or the unit
    # reads as healthy while the mart is behind. DISABLED and BUSY are exit 0:
    # one is the operator's choice, the other another run already doing the
    # work, and a timer that fails for either trains people to ignore it.
    return 1 if result.status == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
