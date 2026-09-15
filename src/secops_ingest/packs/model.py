"""What a pack declares.

A pack bundles one vendor's connectors, transform targets and dashboards into a
distribution that installs and versions on its own.

Sources are `"module:attr"` strings rather than Source objects, and that is
deliberate: importing a connector pulls in its optional dependencies, so eager
objects here would make discovery fail on a core-only install. Strings also
preserve the distinction cli.py protects -- "this source is not registered" is a
different failure from "the connector raised ImportError".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..schema import validate_identifier

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps imports lazy
    from ..transform.base import Target


@dataclass(frozen=True)
class Pack:
    """One installable unit: connectors, targets and dashboards for a vendor."""

    #: Reaches SQL and the CLI, so it must be a plain lowercase identifier.
    name: str
    version: str
    #: Range of core versions this pack works against, e.g. ">=0.2,<0.3".
    requires_core: str
    #: source name -> "module:attr", imported only when the source is run.
    sources: Mapping[str, str]
    targets: Sequence[Target] = ()
    dashboards: Sequence[Path] = ()
    #: pip extras the connectors need, for diagnostics rather than installation.
    extras: Sequence[str] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.name)
        for source_name, target in self.sources.items():
            validate_identifier(source_name)
            module, sep, attr = target.partition(":")
            if not sep or not module or not attr or ":" in attr:
                raise ValueError(
                    f"source {self.name}.{source_name} must be 'module:attr', got {target!r}"
                )
