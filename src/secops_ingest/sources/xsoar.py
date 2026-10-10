"""Cortex XSOAR 8 connector -- pulls incidents.

XSOAR holds the incident lifecycle timestamps behind MTTR and SLA reporting,
and it holds them for longer than XDR does: measured 2026-09-14, this tenant
goes back to 2023-12-10 against XDR's 325-day retention. It also carries the
XDR incident id on every mirrored incident, so it is the anchor for the
end-to-end join. Build this connector before the XDR one.

THE DATE RANGE GOES INSIDE `filter`.

A `fromDate` at the top level of the request body -- alongside `filter`, where
the vendor documentation appears to put it -- is accepted and silently
discarded. Measured against this tenant:

    top-level  fromDate=now-7d   ->  total 48,678   (the whole collection)
    filter.fromDate=now-7d       ->  total 560
    filter.modified.gte=now-7d   ->  total 48,678   (also ignored)

Nothing errors. A connector built on the top-level form re-reads the entire
collection every run and looks like it is working.

NO `filter.query`, EVER. Public guidance says setting it makes page, size and
sort be ignored. That did NOT reproduce here -- the query is applied and paging
still works -- but the failure it warns about is silent under-ingestion, and
`filter.fromDate` already does everything this connector needs. There is
nothing to win and a silent-loss bug to lose.

Configuration:

    SECOPS_XSOAR_SECRET      secret name to resolve (default xsoar)
    SECOPS_XSOAR_PAGE_SIZE   incidents per request  (default 100)
    SECOPS_XSOAR_BACKFILL_DAYS  horizon on first run (default 90)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

from ..common.http import with_retries
from ..common.payload import to_json
from ._cortex import CortexCreds, env_int, headers, resolve

log = logging.getLogger(__name__)

API_PATH = "/xsoar/public/v1"
SEARCH = "/incidents/search"

# How far back the FIRST run reaches. After that the watermark governs, so this
# bounds one run, not every run.
#
# It exists because the live tenant holds incidents back to 2022-04-11 while the
# warehouse partitions a five-month window: the first real run asked for the
# whole collection and died landing its first row with "no partition of relation
# incidents found for row ... 2022-04-11". Matching xdr_alerts' default of 90
# keeps the three Cortex connectors answering the same question the same way.
DEFAULT_BACKFILL_DAYS = 90

#: Deliberately far below the maximum the API accepts. Measured page timings on
#: this tenant: 100 rows 5.3s, 500 rows 9.6s, 1000 rows 16.5s. The failure mode
#: is asymmetric -- a small page costs an extra round trip, while a large page
#: that exceeds the HTTP timeout is retried five times by with_retries, turning
#: a slow endpoint into minutes of silence.
DEFAULT_PAGE_SIZE = 100


class XsoarSource:
    name = "xsoar"
    table = "raw_xsoar.incidents"

    def __init__(self) -> None:
        self.secret = os.environ.get("SECOPS_XSOAR_SECRET", "xsoar")
        self.page_size = env_int("SECOPS_XSOAR_PAGE_SIZE", DEFAULT_PAGE_SIZE)
        self.backfill_days = env_int("SECOPS_XSOAR_BACKFILL_DAYS",
                                     DEFAULT_BACKFILL_DAYS)

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        self._creds: CortexCreds = resolve(self.secret, API_PATH)
        return headers(self._creds)

    # -- fetching -----------------------------------------------------------

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield incidents modified at or after `cursor`, oldest first.

        `toDate` is pinned at run start. Without an upper bound, incidents
        modified while the scan is in progress enter the result set and shift
        every later record one place forward, so a page boundary silently skips
        a row rather than repeating one. Repeating is free -- landing is an
        upsert -- and skipping is data loss, so the bound exists to make the
        error fall on the harmless side.
        """
        now = self._now()
        to_date = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        from_date = str(cursor) if cursor else self._horizon(now)
        page = 0
        while True:
            body: dict[str, Any] = {
                "filter": {
                    "size": self.page_size,
                    "page": page,
                    "sort": [{"field": "modified", "asc": True}],
                    # INSIDE filter. See the module docstring: at the top level
                    # this is accepted and ignored.
                    "toDate": to_date,
                }
            }
            # Always set, now. Omitting it on a first run means "the whole
            # collection", which is the bug this floor fixes.
            body["filter"]["fromDate"] = from_date

            started = time.monotonic()
            # partial, not a lambda: a lambda would close over the loop variable.
            payload = with_retries(partial(self._post, creds, body))
            rows = payload.get("data") or []
            log.info("page %d: %d incident(s) in %.1fs (total=%s)",
                     page, len(rows), time.monotonic() - started, payload.get("total", "?"))
            if not rows:
                return
            yield from rows
            if len(rows) < self.page_size:
                return
            page += 1

    def _now(self) -> datetime:
        """Separated so tests can freeze the clock, as xdr_alerts does."""
        return datetime.now(UTC)

    def _horizon(self, now: datetime) -> str:
        """The bounded start for a run with no watermark."""
        floor = now - timedelta(days=self.backfill_days)
        log.info("no watermark: starting at the bounded horizon of %d day(s), "
                 "not at the beginning of the collection", self.backfill_days)
        return floor.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _post(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One search call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(f"{self._creds.base}{SEARCH}", json=body,
                          headers=headers(self._creds), timeout=90.0)
        resp.raise_for_status()
        return dict(resp.json())

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map an incident to a row.

        `_event_time` is `created`, which never changes. The watermark is
        `modified`, which changes every time the incident is touched -- and
        touching it is the entire point of this connector. Partitioning on the
        watermark field would move a row between partitions on every update.
        """
        return (
            str(record["id"]),
            to_json(record, identifier=str(record["id"])),
            record["created"],
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return record["modified"]


SOURCE = XsoarSource()
