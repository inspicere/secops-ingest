"""Cortex XDR connector -- pulls incidents.

Counterpart to the XSOAR connector. XDR holds the authoritative detection-side
state; XSOAR holds the response lifecycle and a longer history. The two join on
the XDR incident id, which XSOAR carries as `dbotMirrorId`.

THE WATERMARK IS modification_time, NOT creation_time.

An incident is created once and then triaged, assigned, escalated and resolved.
A watermark on `creation_time` reads each incident exactly once, on the day it
opens, and never sees it again -- so every resolution is invisible and an MTTR
dashboard reports nothing. Measured on this tenant: a 7-day window returns 549
incidents filtered on modification_time against 545 on creation_time. Those
four are incidents opened earlier and resolved inside the window, which is
precisely the population the reporting exists to measure.

The failure is silent. Rows arrive, counts rise, nothing errors.

Configuration:

    SECOPS_XDR_SECRET      secret name to resolve (default xdr)
    SECOPS_XDR_PAGE_SIZE   incidents per request  (default 100, hard cap 100)
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
INCIDENTS = "/incidents/get_incidents/"

#: `search_to - search_from` above this returns HTTP 400. Measured 2026-09-14:
#: 100 succeeds, 200 and 1000 are rejected. Not a tunable -- a larger value does
#: not fail gracefully by truncating, it fails the request.
PAGE_CAP = 100


class XdrSource:
    name = "xdr"
    table = "raw_xdr.incidents"

    def __init__(self) -> None:
        self.secret = os.environ.get("SECOPS_XDR_SECRET", "xdr")
        # Clamped rather than rejected: an operator raising this is reaching for
        # throughput, and failing their deploy over it helps nobody. The cap is
        # the API's, not a preference.
        self.page_size = min(env_int("SECOPS_XDR_PAGE_SIZE", PAGE_CAP), PAGE_CAP)

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        self._creds: CortexCreds = resolve(self.secret, API_PATH)
        return headers(self._creds)

    # -- fetching -----------------------------------------------------------

    def _now_ms(self) -> int:
        """Separated so tests can freeze the clock."""
        return int(time.time() * 1000)

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield incidents modified at or after `cursor`, oldest first.

        `gte` rather than `gt`: the cursor's own millisecond is shared by every
        incident modified in that instant, and a strict comparison would drop
        all of them but the one that set the watermark. Re-reading the boundary
        costs nothing because landing is an upsert keyed on
        (source_id, _event_time).

        THE UPPER BOUND IS PINNED ONCE, BEFORE THE FIRST PAGE. This connector
        sorts ascending on the very field it filters on, and `get_incidents`
        pages by offset. An incident touched while the scan is in progress moves
        to the END of that sort, shifting every row behind it one place forward,
        so the next offset window starts past a row that was never returned. The
        loss is permanent, not transient: the skipped row's modification_time is
        below the watermark this run then advances to, so no later run asks for
        it either.

        Pinning an upper bound at run start makes the result set stable for the
        length of the scan, exactly as xsoar.py pins `toDate`. Anything modified
        after the pin is simply picked up next run. `operator: "lte"` on
        modification_time was verified accepted (HTTP 200) against the live
        tenant on 2026-09-14.
        """
        filters: list[dict[str, Any]] = []
        if cursor:
            filters.append({"field": "modification_time", "operator": "gte",
                            "value": int(cursor)})
        filters.append({"field": "modification_time", "operator": "lte",
                        "value": self._now_ms()})

        frm = 0
        while True:
            body = {"request_data": {
                "filters": filters,
                "search_from": frm,
                "search_to": frm + self.page_size,
                "sort": {"field": "modification_time", "keyword": "asc"},
            }}
            started = time.monotonic()
            payload = with_retries(partial(self._post, creds, body))
            reply = payload.get("reply") or {}
            rows = reply.get("incidents") or []
            log.info("window %d-%d: %d incident(s) in %.1fs (total=%s)",
                     frm, frm + self.page_size, len(rows),
                     time.monotonic() - started, reply.get("total_count", "?"))
            if not rows:
                return
            yield from rows
            if len(rows) < self.page_size:
                return
            frm += self.page_size

    def _post(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One get_incidents call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(f"{self._creds.base}{INCIDENTS}", json=body,
                          headers=creds, timeout=90.0)
        resp.raise_for_status()
        return dict(resp.json())

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map an incident to a row.

        XDR timestamps are epoch MILLISECONDS. Dividing by 1000 is not optional:
        feeding the raw value to a timestamp constructor puts every incident in
        roughly the year 56,000, which is obvious on a chart and invisible in a
        single number.
        """
        return (
            str(record["incident_id"]),
            to_json(record, identifier=str(record["incident_id"])),
            datetime.fromtimestamp(int(record["creation_time"]) / 1000, tz=UTC),
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return int(record["modification_time"])


SOURCE = XdrSource()
