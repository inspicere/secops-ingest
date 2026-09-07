"""Watermark ordering.

Regression tests for a silent data-loss defect: comparing timestamps as strings
lets the watermark jump forward past records that are then never re-fetched.
"""

from __future__ import annotations

import pytest

from secops_ingest.common.watermark import comparable as _comparable
from secops_ingest.common.watermark import newer as _newer
from secops_ingest.redaction import register_secret, scrub

# --- the data-loss case -----------------------------------------------------

def test_mixed_utc_offsets_order_by_instant_not_text() -> None:
    """The exact defect: +02:00 noon is EARLIER than 10:30Z, but sorts later."""
    later_instant = "2026-09-04T10:30:00Z"          # 10:30 UTC
    earlier_instant = "2026-09-04T12:00:00+02:00"   # 10:00 UTC

    # String comparison gets this backwards - this is what the bug relied on.
    assert earlier_instant > later_instant

    # Correct behaviour: the earlier instant must not advance the watermark.
    assert _newer(later_instant, earlier_instant) is True
    assert _newer(earlier_instant, later_instant) is False


def test_epoch_strings_order_numerically() -> None:
    """'9999999999' > '10000000000' as text, but is the smaller number."""
    # Comparing two literals is the point: it pins the lexical ordering
    # that comparable() exists to correct.
    assert "9999999999" > "10000000000"  # noqa: PLR0133
    assert _newer("10000000000", "9999999999") is True
    assert _newer("9999999999", "10000000000") is False


def test_zulu_and_offset_parse_to_same_instant() -> None:
    assert _comparable("2026-09-04T10:00:00Z") == _comparable("2026-09-04T12:00:00+02:00")


# --- ordering safety --------------------------------------------------------

def test_none_current_always_advances() -> None:
    assert _newer("2026-09-04T00:00:00Z", None) is True


def test_refuses_to_order_across_types() -> None:
    """A format change mid-run must not advance on a bogus comparison."""
    assert _newer("1757000000", "2026-09-04T10:00:00Z") is False


def test_unparsable_falls_back_to_string_without_raising() -> None:
    assert _comparable("not-a-timestamp") == "not-a-timestamp"
    assert _newer("b-value", "a-value") is True


@pytest.mark.parametrize("value,expected_type", [
    ("2026-09-04T10:00:00Z", "datetime"),
    ("1757000000", "int"),
    ("garbage", "str"),
])
def test_comparable_normalisation(value: str, expected_type: str) -> None:
    assert type(_comparable(value)).__name__ == expected_type


# --- scrubbing before persistence ------------------------------------------

def test_scrub_removes_registered_secret_from_error_text() -> None:
    register_secret("tok_abcdefghijklmnop")
    text = "HTTPStatusError: 401 for https://api.example/v1?token=tok_abcdefghijklmnop"
    out = scrub(text)
    assert "tok_abcdefghijklmnop" not in out
    assert "***REDACTED***" in out


def test_scrub_ignores_short_values() -> None:
    register_secret("abc")
    assert scrub("abc stays") == "abc stays"
