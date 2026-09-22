"""State helpers that need no database."""

from __future__ import annotations

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.packs.state import PackState


def test_packstate_is_frozen() -> None:
    s = PackState(name="vendor", version="1.0", state="ENABLED", enabled_at=None, disabled_at=None)
    with pytest.raises(AttributeError):
        s.state = "DISABLED"  # type: ignore[misc]


def test_only_two_states_are_accepted() -> None:
    from secops_ingest.packs.state import validate_state

    assert validate_state("ENABLED") == "ENABLED"
    with pytest.raises(ValueError, match="ENABLED"):
        validate_state("off")
