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
        """Yield alerts created at or after the cursor, minus the lag window."""
        since = self._since(cursor)
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
            yield from rows
            if len(rows) < self.page_size:
                return
            frm += self.page_size

    def _post(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One get_alerts call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(f"{self._creds.base}{ALERTS}", json=body,
                          headers=creds, timeout=120.0)
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


SOURCE = XdrAlertsSource()
