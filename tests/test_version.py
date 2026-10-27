"""__version__ and pyproject.toml must agree.

They are duplicated deliberately (see secops_ingest/__init__.py), which is
exactly why something has to check them: `pack list` compares the installed
version with control.pack.version, and a pack's requires_core is checked
against __version__, so a bump made in one place only would make both
comparisons quietly wrong.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from secops_ingest import __version__
from secops_ingest.packs.version import parse_version


def test_package_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    assert tomllib.loads(pyproject.read_text())["project"]["version"] == __version__


def test_package_version_is_inside_the_grammar_packs_are_checked_with() -> None:
    parse_version(__version__)
