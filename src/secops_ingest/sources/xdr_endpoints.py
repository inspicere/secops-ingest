"""Cortex XDR connector -- daily endpoint snapshot.

Answers "is the agent estate healthy and are policies actually applied", which
is the policy-health and coverage half of the reporting. Measured 2026-09-14:
1,630 endpoints on this tenant, so a full snapshot is 17 pages and cheap.

A SNAPSHOT, NOT AN INCREMENTAL READ.

Every other connector here asks "what changed since the watermark". This one
asks "what does the estate look like right now", because an endpoint has no
useful modification timestamp to filter on and the interesting question is
drift over time: an agent that stopped checking in, a policy that stopped being
applied, a version that fell behind.

So the cursor is ignored, and every row in a run carries the SAME
`_event_time` -- the moment the snapshot started. That makes each day's
snapshot a distinct set of rows in its own partition, and turns policy state
into a time series rather than a current-state table that overwrites its own
history. The primary key (endpoint_id, snapshot time) does the rest.

Because the whole estate is re-read every run, the watermark exists only to
record that a run happened; nothing filters on it.

Configuration:

    SECOPS_XDR_ENDPOINTS_SECRET     secret name to resolve (default xdr)
    SECOPS_XDR_ENDPOINTS_PAGE_SIZE  endpoints per request  (default 100, cap 100)
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
ENDPOINTS = "/endpoints/get_endpoint/"

PAGE_CAP = 100


class XdrEndpointsSource:
    name = "xdr_endpoints"
    table = "raw_xdr.endpoint_snapshots"

    def __init__(self) -> None:
        self.secret = os.environ.get("SECOPS_XDR_ENDPOINTS_SECRET", "xdr")
        self.page_size = min(env_int("SECOPS_XDR_ENDPOINTS_PAGE_SIZE", PAGE_CAP),
                             PAGE_CAP)
        self._pinned: str | None = None

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        self._creds: CortexCreds = resolve(self.secret, API_PATH)
        self._pinned = None
        return headers(self._creds)

    # -- fetching -----------------------------------------------------------

    def _snapshot_at(self) -> str:
        """The one timestamp every row in this run shares.

        Pinned on first use rather than computed per row: rows landing either
        side of midnight would otherwise split one snapshot across two
        partitions and read as two half-sized estates.
        """
        if self._pinned is None:
            self._pinned = datetime.now(UTC).isoformat()
        return self._pinned

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield every endpoint. `cursor` is deliberately unused.

        AN EXPLICIT SORT IS NOT COSMETIC HERE. The estate is read with 17
        offset-paged requests, and without a `sort` the server's ordering is
        undefined. If that default order is derived from anything mutable --
        last check-in, status, operational state -- an endpoint that changes
        mid-scan moves within the ordering and the next offset window starts
        past a row that was never returned.

        A missing endpoint in this table does not read as a paging artefact. It
        reads as an agent that vanished from the estate, which is the exact
        false signal this connector exists to avoid raising.

        `endpoint_id` is immutable, so ordering on it is stable across the whole
        scan regardless of what changes underneath. Verified accepted (HTTP 200)
        against the live tenant on 2026-09-14.
        """
        self._snapshot_at()
        frm = 0
        while True:
            body = {"request_data": {"search_from": frm,
                                     "search_to": frm + self.page_size,
                                     "sort": {"field": "endpoint_id",
                                              "keyword": "asc"}}}
            started = time.monotonic()
            payload = with_retries(partial(self._post, creds, body))
            reply = payload.get("reply") or {}
            rows = reply.get("endpoints") or []
            log.info("window %d-%d: %d endpoint(s) in %.1fs (total=%s)",
                     frm, frm + self.page_size, len(rows),
                     time.monotonic() - started, reply.get("total_count", "?"))
            if not rows:
                return
            yield from rows
            if len(rows) < self.page_size:
                return
            frm += self.page_size

    def _post(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One get_endpoint call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(f"{self._creds.base}{ENDPOINTS}", json=body,
                          headers=creds, timeout=90.0)
        resp.raise_for_status()
        return dict(resp.json())

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return (
            str(record["endpoint_id"]),
            to_json(record, identifier=str(record["endpoint_id"])),
            self._snapshot_at(),
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return self._snapshot_at()


SOURCE = XdrEndpointsSource()
