"""python -m secops_ingest.packs list

Reports what this environment can see. Enabled/disabled state lives in the
warehouse and is not read here, so this command needs no database and no
optional dependency.
"""

from __future__ import annotations

import argparse
import logging
import sys

from ..redaction import RedactingFilter
from .registry import DuplicatePack, DuplicateTarget, all_targets, discover


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.packs")
    parser.add_argument("command", choices=["list"])
    parser.parse_args(argv)

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

    try:
        packs = discover()
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


if __name__ == "__main__":
    sys.exit(main())
