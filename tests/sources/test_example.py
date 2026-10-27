"""The reference connector is copied, so it must not teach string-compared watermarks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from secops_ingest.sources.example import ExampleSource


def test_the_cursor_is_compared_as_an_instant_not_as_a_string() -> None:
    """V-45. The same instant written with a +02:00 offset sorts AFTER its Z
    form as a string. Compared as text, a cursor stored that way skipped every
    record in the two hours it misplaces; compared as instants, it skips none."""
    src = ExampleSource()
    src.count = 5
    base = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    cursor_instant = base - timedelta(minutes=3)
    as_plus_two = cursor_instant.astimezone(timezone(timedelta(hours=2))).isoformat()

    got = [r["updatedAt"] for r in src.fetch({}, as_plus_two)]

    # Records at base, base-1m and base-2m are newer than base-3m.
    assert len(got) == 3
