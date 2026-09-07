"""python -m secops_ingest.transform <target>"""

from __future__ import annotations

import argparse
import logging
import sys

from ..redaction import RedactingFilter
from . import runner
from .targets import TARGETS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.transform")
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
    )

    log = logging.getLogger(__name__)
    try:
        result = runner.execute(TARGETS[args.target])
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
