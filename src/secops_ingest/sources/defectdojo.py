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
scans the whole collection by id -- the only indexed ordering -- and filters in
process, because a full scan on an indexed column is several times cheaper than
a partial scan on an unindexed one. See `fetch` for the measurements.

Configuration:

    SECOPS_DEFECTDOJO_URL        base URL, e.g. https://dojo.example.com
    SECOPS_DEFECTDOJO_SECRET     secret name (default defectdojo_api_token)
    SECOPS_DEFECTDOJO_PAGE_SIZE  results per request (default 1000)
    SECOPS_DEFECTDOJO_TIMEOUT_SEC
                                 per-request timeout in seconds (default 120)
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

from ..common.http import RetryBudgetExhausted, with_retries
from ..common.payload import to_json
from ..common.watermark import comparable
from ..secrets import get_provider

log = logging.getLogger(__name__)

#: One page size, because there is now one ordering. 1000, chosen from the worst
#: page measured rather than from caution.
#:
#: Sampled across the id range at limit=200, from the host the connector runs
#: on, pages run 0.4-1.9 MB -- the heaviest region is the oldest ids. A
#: 1000-record page there is 4.9 MB and 13.2s, which is 22% of
#: DEFAULT_TIMEOUT_SEC. The whole collection (~52k findings, ~176 MB) is ~52
#: requests and about five minutes.
#:
#: PAGE SIZE CANNOT BOUND RESPONSE SIZE and never could: a finding carrying a
#: scan dump in its description is 100x a typical one, and such findings cluster
#: by id because one import writes many at once. So the real guard is the
#: timeout below, and this number only trades request count against page weight.
DEFAULT_PAGE_SIZE = 1000

#: Was hardcoded at 60.0, two seconds above the 58-59s pages that were killing
#: incremental runs. Raised and made configurable because bytes per page are
#: unbounded (see above), so a deployment with heavier findings needs room
#: without editing the package.
DEFAULT_TIMEOUT_SEC = 120

#: Floor for shrink-on-timeout. Below this a timeout is a broken server rather
#: than a large page, and walking ~52k findings 25 at a time through a server
#: that cannot answer would take longer than any unit timeout allows. Failing
#: loudly at the floor is the honest outcome.
MIN_PAGE_SIZE = 25

#: Divisor for each shrink step: 1000 -> 250 -> 62 -> 25 (floor). Four sizes
#: rather than a gentle ramp, because each attempt costs a full timeout and the
#: point is to find a size that works quickly, not to probe politely.
SHRINK_FACTOR = 4

#: Attempts per page size: ONE.
#:
#: This was two, and a measured full scan showed what the second attempt costs.
#: Six pages of the shrink ladder consumed 13.4 minutes of a 39-minute run,
#: because every size was tried twice at a 120s timeout before shrinking. The
#: second attempt is a request already known to be too large: it cannot succeed
#: for a different reason, and it costs a full timeout to learn nothing.
#:
#: Non-timeout failures are unaffected -- those still go through with_retries
#: below with its full budget, because a 5xx or a dropped connection genuinely
#: may succeed on a second try. Only the too-large case shrinks immediately.
PAGE_ATTEMPTS = 1

#: Consecutive successes before trying a larger page again, and it DOUBLES after
#: every timeout.
#:
#: Recovery matters less than it looks: the measured run's tail cost 1.8 minutes
#: of 39, so climbing back is a small win. Getting it wrong is a large loss --
#: the slow band was ~28 pages wide, and growing back every few pages would have
#: re-paid a timeout again and again while crossing it. Doubling the threshold
#: means a region that keeps refusing is asked progressively less often, so the
#: cost of optimism is bounded no matter how wide the bad region is.
GROW_AFTER = 4

#: The only ordering. `id` is indexed; `last_status_update` is not, so ordering
#: on it makes PostgreSQL sort the whole collection for EVERY request. Measured
#: from the connector's own host:
#:
#:     limit=25    o=-last_status_update    51.3s   10.5 MB    206 KB/s
#:     limit=100   o=-last_status_update    TIMED OUT at 200s
#:     limit=1000  o=-id                     5.4s    8.4 MB   1.56 MB/s
#:
#: DESCENDING, not ascending, and it matters for one reason only: offset
#: pagination over a mutable collection. A finding modified mid-scan does not
#: move under `-id` -- ids do not change -- so unlike the old modification-time
#: ordering, a page boundary neither re-reads nor skips because of an update. A
#: finding CREATED mid-scan gets the highest id and lands at the front,
#: shifting later records one place back, so a boundary re-reads a record rather
#: than skipping one, which the upsert absorbs. Ascending would put new findings
#: at the END, past the last page the scan computed, so they would be missed
#: until the next run -- harmless but needlessly late.
ORDER_BY = "-id"

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
        self.timeout_sec = _env_int("SECOPS_DEFECTDOJO_TIMEOUT_SEC", DEFAULT_TIMEOUT_SEC)

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
        """Scan the whole collection by id, yielding only what changed.

        WHY A FULL SCAN IS CHEAPER THAN A PARTIAL ONE. The API has no filter on
        the modification axis -- `last_status_update` takes an exact match and
        has no range variant, and an unknown parameter is silently ignored
        rather than rejected, so no spelling of it works. The previous design
        therefore sorted by modification time descending and stopped at the
        first record older than the cursor, reading only the changed head.

        Measured 2026-10-18, that head is not reliably small and the ordering is
        not indexed. A live run paged at 58-59s against a 60s request timeout
        and reached 200 records in 11.5 minutes before the unit timeout killed
        it -- having committed those rows but not its watermark, so the next run
        repeated the same work. Walking 500 changed records that way costs ~17
        minutes; reading all ~52k by id costs about five.

        So the scan reads everything and filters here. Its cost is a function of
        the collection size rather than of how much changed, which makes a run's
        duration predictable -- the property the old design lacked, because the
        head's byte weight swings 100x as scan imports land.

        WHAT THIS GIVES UP. Cost now scales with the collection: ~5 minutes at
        52k findings, ~18 at 200k, and past roughly 300k it no longer fits
        TimeoutStartSec=1800 and the cap has to rise. `discovered_after` and
        `mitigated_after` DO exist server-side (the convention is _after /
        _before, not __gte) and would scale with changes instead -- but they
        cover only discovery and mitigation, while the mart derives its status
        column from six boolean flags including false_p, duplicate,
        out_of_scope, risk_accepted and active. Filtering on those two axes
        would silently miss most triage activity, so they are not used.

        STRICTLY NEWER, AND NO TIES ARE DROPPED. The run that set the watermark
        to M yielded every record at M, because all of them were newer than the
        cursor it started from. The old design needed a `<` stop to re-read ties
        precisely because it stopped early; a full scan does not.
        """
        offset = 0
        # Run-local, because a timeout reduces it for the REST of the run: a
        # server that refused 1000 once should not be asked for 1000 again, or
        # a long scan re-pays the timeout on every page.
        page_size = self.page_size
        # Per-run paging state. On the instance rather than in locals because
        # _get_page owns the policy and fetch() only carries the current size.
        self._successes = 0
        self._grow_after = GROW_AFTER
        floor = comparable(cursor) if cursor else None
        if floor is None:
            log.info("no watermark: first run reads the whole collection")

        scanned = kept = 0
        while True:
            params = {
                "limit": page_size,
                "offset": offset,
                # `o`, not `ordering`. See the module docstring: the
                # conventional name is accepted and silently ignored.
                "o": ORDER_BY,
            }
            started = time.monotonic()
            payload, used, page_size = self._get_page(creds, offset, page_size)
            params["limit"] = used
            elapsed = time.monotonic() - started
            results = payload.get("results") or []
            scanned += len(results)

            # An empty page ends the scan even when `next` is still set.
            # Restored deliberately: offset past `count` returns an empty list,
            # and trusting `next` alone makes that a loop rather than a stop.
            if not results:
                log.info("empty page at offset=%d; scan complete", offset)
                return

            for record in results:
                mark = self.watermark_of(record)
                # No early return. Ordered by id, an old modification can sit
                # anywhere, so a stop here would truncate the scan at an
                # arbitrary point rather than at the end of the changed set.
                if floor is not None and mark is not None and comparable(mark) <= floor:
                    continue
                kept += 1
                yield record

            # Per-page progress. A full scan is minutes long by design, and
            # without a line per page that is indistinguishable from a hang.
            log.info(
                "page offset=%d records=%d in %.1fs (scanned=%d kept=%d total=%s)",
                offset, len(results), elapsed, scanned, kept,
                payload.get("count", "?"),
            )

            if not payload.get("next"):
                log.info("scan complete: %d findings read, %d changed", scanned, kept)
                return
            # `used`, not `page_size`: page_size is what the NEXT request will
            # ask for, which may be larger. Advancing by it would skip every
            # record between the two.
            offset += used

    def _get_page(
        self, creds: Any, offset: int, page_size: int
    ) -> tuple[dict[str, Any], int, int]:
        """Fetch one page, shrinking it rather than repeating it on a timeout.

        `with_retries` retries the IDENTICAL request. For a 5xx or a dropped
        connection that is right; for a timeout it is not, because the same
        request will time out again for the same reason. Measured against a
        DefectDojo at load 48, five attempts at a 120s timeout produced ten
        minutes of silence and then a failed run -- which is how a transient
        server problem became a livelocked one, since the run committed rows but
        never its watermark.

        A timeout means the request was too large to answer, so this asks for
        less AT THE SAME OFFSET. Nothing is skipped: the offset only advances
        once a page has actually been returned.

        Returns the payload, THE SIZE THIS PAGE ACTUALLY USED, and the size to
        request next. Those last two differ whenever the policy grows the page,
        and conflating them loses data: a 250-record page followed by a jump of
        1000 skips 750 findings without failing anything. The caller advances
        `offset` by the size used and sends the next size on the following
        request.
        """
        import httpx

        size = page_size
        while True:
            params = {"limit": size, "offset": offset, "o": ORDER_BY}
            try:
                payload = with_retries(
                    partial(self._get, creds, params), attempts=PAGE_ATTEMPTS
                )
            except RetryBudgetExhausted as exc:
                # Only a timeout means "too large". A 5xx or a transport error
                # has already been retried, and a smaller page would just ask a
                # broken endpoint the same thing more slowly.
                if not isinstance(exc.__cause__, httpx.TimeoutException):
                    raise
                if size <= MIN_PAGE_SIZE:
                    log.error(
                        "offset=%d still timing out at limit=%d, the floor; "
                        "the server cannot serve this collection right now",
                        offset, size,
                    )
                    raise
                smaller = max(MIN_PAGE_SIZE, size // SHRINK_FACTOR)
                # Each timeout makes the next attempt to grow back more
                # reluctant, so a wide slow region is probed a handful of times
                # rather than once per few pages.
                self._grow_after *= 2
                self._successes = 0
                log.warning(
                    "offset=%d timed out at limit=%d; retrying at limit=%d "
                    "(will reconsider after %d clean pages)",
                    offset, size, smaller, self._grow_after,
                )
                size = smaller
                continue

            self._successes += 1
            # Growth applies to the NEXT request, never to the page just
            # served: `size` is what this page used and the offset advances by
            # it.
            next_size = size
            if size < self.page_size and self._successes >= self._grow_after:
                larger = min(self.page_size, size * SHRINK_FACTOR)
                if larger != size:
                    log.info(
                        "%d clean pages at limit=%d; trying limit=%d again",
                        self._successes, size, larger,
                    )
                    next_size = larger
                self._successes = 0
            return payload, size, next_size

    def _get(self, creds: Any, params: dict[str, Any]) -> dict[str, Any]:
        """One API call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.get(
            f"{self.url}/api/v2/findings/",
            params=params,
            headers=creds,
            verify=self._tls_verify(),
            timeout=float(self.timeout_sec),
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
