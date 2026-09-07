"""Watermark ordering.

Kept free of any database dependency so the ordering rules - which are where a
silent data-loss defect lived - are testable without a driver installed.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

_warned_unparsable: set[str] = set()


def comparable(value: Any) -> Any:
    """Normalise a watermark to something safely orderable.

    Comparing timestamps as strings is unsafe and can LOSE DATA: with mixed UTC
    offsets, "2026-09-04T12:00:00+02:00" sorts after "2026-09-04T10:30:00Z"
    despite being the earlier instant, so the watermark can jump forward past
    records that are then never re-fetched. Epoch integers rendered as strings
    misorder the same way ("9999999999" > "10000000000").
    """
    if isinstance(value, (datetime, int, float)):
        return value
    text = str(value)
    if text.isdigit():
        return int(text)
    try:
        # No Z -> +00:00 rewrite: fromisoformat parses the military suffix
        # itself from 3.11, which is this package's floor.
        return datetime.fromisoformat(text)
    except ValueError:
        if text[:4] not in _warned_unparsable:
            _warned_unparsable.add(text[:4])
            log.warning(
                "watermark %r is neither a timestamp nor an epoch; falling back to "
                "string ordering, which is unsafe across format changes", text
            )
        return text


def newer(candidate: Any, current: Any) -> bool:
    """True if `candidate` should advance the watermark past `current`."""
    if current is None:
        return True
    a, b = comparable(candidate), comparable(current)
    if type(a) is not type(b):
        # A format change mid-run: refuse to order across types rather than
        # advance the watermark on a bogus comparison.
        log.warning("watermark type changed (%s -> %s); not advancing",
                    type(b).__name__, type(a).__name__)
        return False
    return bool(a > b)
