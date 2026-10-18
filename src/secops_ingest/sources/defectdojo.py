"""DefectDojo connector — pulls vulnerability findings.

DefectDojo is an open-source (BSD-3-Clause) vulnerability management platform.
It is the counterpart to the Wazuh connector, and the pair is deliberate:

    Wazuh        alerts are APPEND-ONLY. The event time is the watermark.
                 The hazard is late arrival, handled with an overlap window.

    DefectDojo   findings MUTATE for months. A finding is created once and then
                 triaged, verified, risk-accepted, mitigated, reopened. Creation
                 time and modification time are different fields, and confusing
                 them is the single most expensive mistake available here.

A watermark on `created` reads every finding exactly once, on the day it
appears, and never sees it again. Every subsequent mitigation is invisible, so
findings closed months ago still show as open and the SLA numbers are wrong in
the flattering direction. The failure is silent: rows arrive, counts rise,
nothing errors.

    python -m secops_ingest defectdojo

THE API HAS TWO TRAPS, BOTH SILENT

1. Unknown query parameters are IGNORED, not rejected. `?nonsense=xyzzy`
   returns the full unfiltered collection with HTTP 200. So a wrong parameter
   name does not fail — it quietly returns everything, and a connector built on
   one looks like it works while re-reading the entire table every run.

2. The ordering parameter is `o=`, NOT the DRF-conventional `ordering=`.
   `ordering=-id` is silently ignored per trap 1; `o=-id` works. This was found
   by checking that a deliberately bogus parameter produced the same response
   as the plausible one.

There is no server-side filter ON THE MODIFICATION AXIS, which is the one this
connector needs. `last_status_update__gt`, `__gte`, `created__gt` and `date__gt`
are all ignored -- but so is any invented name, per trap 1, so their silence
proved nothing about whether a filter exists.

Reading the OpenAPI schema instead of guessing (2026-10-17) shows the real
convention is `_after` / `_before`, and two such filters DO work:

    discovered_after=2026-07-20     48,845 -> 7,793
    mitigated_after=2026-10-01      48,845 ->   616

Neither is the modification axis. `last_status_update` is an exact-match filter
with no range variant, so "what changed since X" remains unaskable and the early
stop below is still the answer. `discovered_after` would bound a backfill by
DISCOVERY date, which is deliberately not used: it would permanently exclude a
finding discovered two years ago and modified yesterday, and the warehouse keeps
seven years of history for year-over-year reporting.

So this connector cannot ask for "what changed" the way the Wazuh one does. It
sorts by modification time descending and stops as soon as it reaches records
older than the watermark, reading only the changed head of the collection.

Configuration:

    SECOPS_DEFECTDOJO_URL        base URL, e.g. https://dojo.example.com
    SECOPS_DEFECTDOJO_SECRET     secret name (default defectdojo_api_token)
    SECOPS_DEFECTDOJO_PAGE_SIZE  results per request on an INCREMENTAL run
                                 (default 25 -- see below)
    SECOPS_DEFECTDOJO_BACKFILL_PAGE_SIZE
                                 results per request on a BACKFILL (default
                                 1000; the backfill sorts on an indexed column
                                 and 25 cannot finish inside the unit timeout)
    SECOPS_DEFECTDOJO_CA_BUNDLE  CA bundle for the API's certificate
    SECOPS_DEFECTDOJO_INSECURE   set to 1 to skip TLS verification (logged)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from functools import partial
from typing import Any

from ..common.http import with_retries
from ..common.payload import to_json
from ..common.watermark import comparable
from ..secrets import get_provider

log = logging.getLogger(__name__)

#: Deliberately small. Finding payloads vary enormously -- a typical one is ~3KB,
#: but a finding carrying a scan dump in its description can be 100x that -- so
#: page size is not a reliable throttle on response size. Measured against a live
#: instance holding ~50k findings:
#:
#:     limit=25    0.4s     76 KB
#:     limit=50   29.0s    5.9 MB      <- one large finding lands in the page
#:     limit=100  did not return within 120s
#:
#: The failure mode is asymmetric. A small page costs extra round trips; a large
#: page exceeds the HTTP timeout, and with_retries then retries it five times,
#: turning a slow endpoint into several minutes of silence. Err small.
DEFAULT_PAGE_SIZE = 25

#: Backfill page size, forty times the incremental one, and the asymmetry is the
#: whole point: THE TWO PATHS DO NOT COST THE SAME, because they do not sort on
#: the same column.
#:
#: The note above is about `-last_status_update`, which has no index. This is
#: about `-id`, which does. Re-measured 2026-10-17 against a 48,845-finding
#: instance, one page at offset=20000:
#:
#:     o=-id                   limit=25      3.24s     69 KB
#:     o=-id                   limit=100     3.51s    275 KB
#:     o=-id                   limit=500     5.16s    1.4 MB
#:     o=-id                   limit=1000    7.44s    2.7 MB
#:     o=-last_status_update   limit=25      2.06s    110 KB
#:     o=-last_status_update   limit=100    90.31s   17.4 MB
#:     o=-last_status_update   limit=500    TIMED OUT at 180s
#:
#: A 40x larger page costs 2.3x the time on the indexed ordering, because a
#: fixed ~1.7s per request dominates. So the arithmetic that matters:
#:
#:     limit=25     1,954 requests   ~105 min   exceeds the 1800s unit timeout
#:     limit=1000      49 requests     ~6 min   comfortable
#:
#: THIS IS WHY THE BACKFILL COULD NEVER FINISH. It was not the byte rate. One
#: page size was shared by a path that must stay small and a path that must not,
#: and 25 is correct for the first and unusable for the second. The unit was
#: killed at its timeout, having committed rows but not its watermark, so the
#: next run restarted the same backfill -- progress-free, indefinitely.
#:
#: Do NOT raise the incremental size to match. The table above is why: at
#: limit=100 that ordering takes 90s and returns 17.4 MB, and at 500 it does not
#: return at all.
DEFAULT_BACKFILL_PAGE_SIZE = 1000

#: Incremental ordering. Descending, so the newest modification is the first
#: record returned — see `fetch` for why that is load-bearing.
ORDER_BY = "-last_status_update"

#: Backfill ordering, and the reason is performance rather than taste.
#:
#: last_status_update carries no index in DefectDojo, so ordering on it makes
#: PostgreSQL sort the entire collection for EVERY page. Measured against a
#: ~51k-finding instance:
#:
#:     limit=25                          0.5s
#:     limit=25&o=-id                    0.7s
#:     limit=25&o=-last_status_update   43.4s
#:     limit=25&o=-id&offset=40000       0.4s   (offset itself is free)
#:
#: An incremental run reads a handful of pages and can afford it. A backfill
#: reads ~2,000, which is 24 hours against 20 minutes.
#:
#: Ordering by id is safe for a backfill precisely because a backfill has no
#: early stop to support: it reads everything, so the order records arrive in
#: does not affect what is collected. The watermark is still correct because the
#: framework keeps the MAXIMUM watermark it observes, not the last one.
ORDER_BY_BACKFILL = "-id"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 1:
        raise ValueError(f"{name} must be >= 1, got {value}")
    return value


class DefectDojoSource:
    name = "defectdojo"
    table = "raw_defectdojo.findings"

    def __init__(self) -> None:
        self.url = (os.environ.get("SECOPS_DEFECTDOJO_URL") or "").rstrip("/")
        self.secret_name = os.environ.get("SECOPS_DEFECTDOJO_SECRET", "defectdojo_api_token")
        self.page_size = _env_int("SECOPS_DEFECTDOJO_PAGE_SIZE", DEFAULT_PAGE_SIZE)
        self.backfill_page_size = _env_int(
            "SECOPS_DEFECTDOJO_BACKFILL_PAGE_SIZE", DEFAULT_BACKFILL_PAGE_SIZE
        )

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        if not self.url:
            raise ValueError("SECOPS_DEFECTDOJO_URL is not set")
        token = get_provider().get(self.secret_name)
        from ..redaction import register_secret

        register_secret(token)
        return {"Authorization": f"Token {token}"}

    # -- fetching -----------------------------------------------------------

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield findings modified at or after `cursor`, newest first.

        The API cannot filter by time, so this walks the collection sorted by
        modification time descending and stops at the first record older than
        the cursor. Only the changed head is read; the other ~50k findings are
        never fetched.

        WHY DESCENDING IS LOAD-BEARING. The first record returned carries the
        highest modification time in the collection, so the watermark the run
        records is the high-water mark *as of the moment the scan started*.
        Anything modified while the scan is in progress is necessarily newer
        than that, so it is picked up by the next run rather than missed. The
        framework already keeps the maximum watermark it sees, so this needs no
        special handling here — but it is the reason ascending order would be
        wrong, and the reason this is not simply a stylistic choice.

        THE STOP IS STRICT. Records exactly at the cursor are re-read every
        run, because the cursor's own timestamp is shared by however many
        findings were written in that same instant — around 50 of them, in a
        bulk scan import. Stopping at `<= cursor` would drop every tie except
        the one that set the watermark. Re-reading them costs nothing: landing
        is an upsert keyed on (source_id, _event_time).

        OFFSET PAGINATION OVER MUTABLE DATA. A finding modified mid-scan jumps
        to the front of the ordering, shifting later records one place back —
        so a page boundary re-reads a record rather than skipping one, which
        the upsert absorbs. A finding *deleted* mid-scan shifts the other way
        and can hide one record until its next modification. That is accepted:
        DefectDojo deletions are rare and administrative, and the alternative
        is keyset pagination, which this API cannot express because it has no
        time filter to key on.
        """
        offset = 0
        floor = comparable(cursor) if cursor else None
        # No cursor means a backfill: read everything, so the expensive ordering
        # that exists only to enable an early stop buys nothing. See
        # ORDER_BY_BACKFILL.
        # Ordering and page size are chosen TOGETHER, from one condition, because
        # the size is only safe for the ordering it accompanies. Deriving them
        # separately is how a large page would reach the unindexed sort.
        if floor is not None:
            order, page_size = ORDER_BY, self.page_size
        else:
            order, page_size = ORDER_BY_BACKFILL, self.backfill_page_size
        if floor is None:
            log.info(
                "no watermark: backfilling the whole collection ordered by %s, "
                "page size %d", order, page_size,
            )

        while True:
            params = {
                "limit": page_size,
                "offset": offset,
                # `o`, not `ordering`. See the module docstring: the
                # conventional name is accepted and silently ignored.
                "o": order,
            }
            started = time.monotonic()
            payload = with_retries(partial(self._get, creds, params))
            elapsed = time.monotonic() - started
            results = payload.get("results") or []
            # Per-page progress. This endpoint gets slow as the collection grows
            # -- ordering 50k findings server-side is not cheap -- and without a
            # line per page a long run looks identical to a hang.
            log.info(
                "page offset=%d records=%d in %.1fs (total=%s)",
                offset, len(results), elapsed, payload.get("count", "?"),
            )
            if not results:
                return

            for record in results:
                mark = self.watermark_of(record)
                if floor is not None and mark is not None and comparable(mark) < floor:
                    # Descending order: everything after this is older still.
                    log.info("reached the watermark at offset=%d; stopping", offset)
                    return
                yield record

            if not payload.get("next"):
                return
            # page_size, not self.page_size: stepping by the incremental size
            # while requesting backfill-sized pages would re-read the same
            # window forever.
            offset += page_size

    def _get(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
        """One API call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.get(
            f"{self.url}/api/v2/findings/",
            params=params,
            headers=creds,
            verify=self._tls_verify(),
            timeout=60.0,
        )
        resp.raise_for_status()
        return dict(resp.json())

    def _tls_verify(self) -> Any:
        bundle = os.environ.get("SECOPS_DEFECTDOJO_CA_BUNDLE")
        if bundle:
            return bundle
        if os.environ.get("SECOPS_DEFECTDOJO_INSECURE") == "1":
            log.warning(
                "TLS verification DISABLED for DefectDojo "
                "(SECOPS_DEFECTDOJO_INSECURE=1). Set SECOPS_DEFECTDOJO_CA_BUNDLE instead."
            )
            return False
        return True

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map a finding to a row.

        `_event_time` is the discovery date, which never changes. The watermark
        is the modification time, which changes constantly. Partitioning on the
        latter would move a row between partitions every time somebody triaged
        it — the partition key has to be immutable.
        """
        return (
            str(record["id"]),
            to_json(record, identifier=str(record["id"])),
            record.get("date") or record["created"],
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        """Modification time, falling back to creation.

        `last_status_update` is null on a finding that has never been touched
        since import. Returning None for those would stall the watermark at the
        start of the collection; `created` is the correct answer for a record
        that has not been modified, because for it the two are the same event.
        """
        return record.get("last_status_update") or record.get("created")


SOURCE = DefectDojoSource()
