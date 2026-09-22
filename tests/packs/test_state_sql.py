"""State helpers that need no database."""

from __future__ import annotations

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

# Deliberately below the importorskip: state.py itself imports psycopg at
# module scope, so importing it before the skip check would turn "postgres
# extra not installed" into a collection-time ImportError instead of a clean
# skip.
from secops_ingest.packs.state import PackState  # noqa: E402


def test_packstate_is_frozen() -> None:
    s = PackState(name="vendor", version="1.0", state="ENABLED", enabled_at=None, disabled_at=None)
    with pytest.raises(AttributeError):
        s.state = "DISABLED"  # type: ignore[misc]


def test_only_two_states_are_accepted() -> None:
    from secops_ingest.packs.state import validate_state

    assert validate_state("ENABLED") == "ENABLED"
    with pytest.raises(ValueError, match="ENABLED"):
        validate_state("off")
