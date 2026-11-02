"""Cortex XDR connector -- pulls alerts.

The detection layer beneath the incidents. Three orders of magnitude larger
than them, which is what dictates everything unusual in this module. Measured
2026-09-14 on this tenant:

    2,650,762 alerts total
    ~17,700/day  (123,952 over 7 days; 14,324 over 24 hours)
    against 9,715 incidents for the same period

A full backfill is ~26,500 requests at the 100-row page cap, and roughly 13GB
of raw JSONB per year on a host shared with Metabase.

TWO THINGS THIS CONNECTOR DOES THAT THE OTHERS DO NOT

1. AN EMPTY WATERMARK MEANS "THE LAST N DAYS", NOT "EVERYTHING". Every other
   connector treats a missing cursor as a backfill. Here that would run for
   hours and land millions of rows nobody asked for. The horizon is bounded and
   configurable; widening it is a deliberate act.

2. THE CURSOR IS REWOUND BY A LAG WINDOW. `local_insert_ts` -- when XDR indexed
   the alert -- trails `detection_timestamp` -- when it happened. Measured over
   100 recent alerts: minimum 7s, median 139s, maximum 627s. Because the only
   filterable field orders by detection time, an alert indexed after the
   watermark has already advanced past its detection time would be stepped over
   and never seen again. So each run re-reads a trailing window. Re-reading is
   free: landing is an upsert keyed on (source_id, _event_time). Losing alerts
   is not.

THE FILTER VOCABULARY IS NOT THE PAYLOAD VOCABULARY. The filterable field is
`creation_time`, which appears nowhere in an alert payload; the payload carries
`detection_timestamp` and `local_insert_ts`. Filtering on either payload name
returns HTTP 500. Verified that `creation_time` orders on detection time by
filtering at a cutoff and checking the minimum `detection_timestamp` returned.

ALERT STATE CHANGES ARE NOT TRACKED. `resolution_status` mutates, but the only
filterable field is the creation time, so there is no way to ask for "alerts
whose status changed". Alerts are captured as at detection. Incident-level
status is the tracked lifecycle -- see the xdr and xsoar connectors.

ALERTS CARRY NO INCIDENT ID. Measured null on every sampled row, so
alert-to-incident attribution is not available from this endpoint at all. Use
the incident's own `alert_count` and `alert_categories` instead of trying to
join 2.65M rows.

Configuration:

    SECOPS_XDR_ALERTS_SECRET         secret name to resolve (default xdr)
    SECOPS_XDR_ALERTS_PAGE_SIZE      alerts per request     (default 100, cap 100)
    SECOPS_XDR_ALERTS_LAG_SECONDS    late-arrival overlap   (default 1800)
    SECOPS_XDR_ALERTS_BACKFILL_DAYS  horizon on first run   (default 90)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from functools import partial
from typing import Any

from ..common import context
from ..common.http import with_retries
from ..common.payload import to_json
from ._cortex import CortexCreds, env_int, headers, resolve

log = logging.getLogger(__name__)

API_PATH = "/public_api/v1"
ALERTS = "/alerts/get_alerts_multi_events/"

PAGE_CAP = 100

#: ~2.9x the worst late arrival measured (627s). Generous on purpose: the cost
#: of overlap is duplicate upserts, and the cost of being wrong is lost alerts.
DEFAULT_LAG_SECONDS = 1800

#: ~1.6M rows at the measured rate. The whole collection would be ~2.65M and
#: most of it will never be read individually.
DEFAULT_BACKFILL_DAYS = 90


class XdrAlertsSource:
    name = "xdr_alerts"
    table = "raw_xdr.alerts"

    #: ORDERED. It sorts and filters on `creation_time` and watermarks
    #: `detection_timestamp`, and `creation_time` orders on detection time
    #: (measured; see the module docstring). So when a run stops early, the
    #: highest detection timestamp it saw is a mark it has read up to. Alerts
    #: XDR indexes later, below that mark, fall inside the lag window the next
    #: run rewinds by: the same guarantee a complete run gives.
    #:
    #: Declared unordered, a run stopped by its deadline kept its cursor and
    #: the next one re-read the same oldest window. At ~16 rows/s a run covers
    #: ~24k alerts, so a first run (~1.6M over the 90-day horizon) or any gap
    #: longer than about a day never caught up, and every run reported
    #: SUCCESS. fetch() checks the ordering as it reads and caps the
    #: watermark if an alert arrives further out of order than the lag window
    #: covers, so the declaration is verified, not assumed.
    fetch_order_is_watermark_order = True

    def __init__(self) -> None:
        self.secret = os.environ.get("SECOPS_XDR_ALERTS_SECRET", "xdr")
        self.page_size = min(env_int("SECOPS_XDR_ALERTS_PAGE_SIZE", PAGE_CAP), PAGE_CAP)
        self.lag_seconds = env_int("SECOPS_XDR_ALERTS_LAG_SECONDS", DEFAULT_LAG_SECONDS)
        self.backfill_days = env_int("SECOPS_XDR_ALERTS_BACKFILL_DAYS",
                                     DEFAULT_BACKFILL_DAYS)

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        self._creds: CortexCreds = resolve(self.secret, API_PATH)
        return headers(self._creds)

    # -- fetching -----------------------------------------------------------

    def _now_ms(self) -> int:
        """Separated so tests can freeze the clock."""
        return int(time.time() * 1000)

    def _since(self, cursor: str | None) -> int:
        now = self._now_ms()
        if not cursor:
            floor = now - self.backfill_days * 86_400_000
            log.info("no watermark: starting at the bounded horizon of %d day(s), "
                     "not at the beginning of the collection", self.backfill_days)
            return floor
        return int(cursor) - self.lag_seconds * 1000

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield alerts created at or after the cursor, minus the lag window.

        Also checks the ordering the run relies on (see
        fetch_order_is_watermark_order). An alert detected more than the lag
        window below the highest mark already yielded means the sort is not
        detection order here, so alerts after a stop could sit below the mark
        by more than the next run rewinds. The watermark is then capped at the
        lowest such alert: the next run re-reads from there rather than
        stepping past anything.
        """
        since = self._since(cursor)
        lag_ms = self.lag_seconds * 1000
        highest: int | None = None
        ceiling: int | None = None
        frm = 0
        while True:
            body = {"request_data": {
                # `creation_time` is the FILTER field. The payload has no such
                # key; see the module docstring.
                "filters": [{"field": "creation_time", "operator": "gte",
                             "value": since}],
                "search_from": frm,
                "search_to": frm + self.page_size,
                "sort": {"field": "creation_time", "keyword": "asc"},
            }}
            started = time.monotonic()
            payload = with_retries(partial(self._post, creds, body))
            reply = payload.get("reply") or {}
            rows = reply.get("alerts") or []
            log.info("window %d-%d: %d alert(s) in %.1fs (total=%s)",
                     frm, frm + self.page_size, len(rows),
                     time.monotonic() - started, reply.get("total_count", "?"))
            if not rows:
                return
            for row in rows:
                mark = _detection_ms(row)
                if mark is not None:
                    if highest is not None and mark < highest - lag_ms:
                        if ceiling is None or mark < ceiling:
                            ceiling = mark
                            log.warning(
                                "alert %s detected at %d, more than the %ds lag "
                                "window below the highest mark read (%d): the "
                                "sort is not detection order here, so the "
                                "watermark is capped at %d",
                                row.get("alert_id"), mark, self.lag_seconds,
                                highest, mark)
                            context.cap_watermark(mark)
                    highest = mark if highest is None else max(highest, mark)
                yield row
            if len(rows) < self.page_size:
                return
            frm += self.page_size

    def _post(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One get_alerts call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(f"{self._creds.base}{ALERTS}", json=body,
                          headers=headers(self._creds), timeout=120.0)
        resp.raise_for_status()
        return dict(resp.json())

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        ts = int(record["detection_timestamp"])
        return (
            str(record["alert_id"]),
            to_json(record, identifier=str(record["alert_id"])),
            datetime.fromtimestamp(ts / 1000, tz=UTC),
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return int(record["detection_timestamp"])


def _detection_ms(record: dict[str, Any]) -> int | None:
    """The record's detection timestamp, or None if it has none usable.

    A record without one is the run's to reject (watermark_of raises); the
    ordering check just leaves it out.
    """
    try:
        return int(record["detection_timestamp"])
    except (KeyError, TypeError, ValueError):
        return None


SOURCE = XdrAlertsSource()
