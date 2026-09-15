"""python -m secops_ingest.packs list

Reports what this environment can see. Enabled/disabled state lives in the
warehouse and is not read here, so this command needs no database and no
optional dependency.
"""

from __future__ import annotations

import argparse
import sys

from .registry import DuplicatePack, DuplicateTarget, all_targets, discover


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_ingest.packs")
    parser.add_argument("command", choices=["list"])
    args = parser.parse_args(argv)
    assert args.command == "list"

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
