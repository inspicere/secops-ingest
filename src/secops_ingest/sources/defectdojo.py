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

There is NO server-side time filter. `last_status_update__gt`, `__gte`,
`created__gt` and `date__gt` are all ignored (verified against a live instance
holding ~50k findings). So this connector cannot ask for "what changed" the way
the Wazuh one does. It sorts by modification time descending and stops as soon
as it reaches records older than the watermark, reading only the changed head
of the collection.

Configuration:

    SECOPS_DEFECTDOJO_URL        base URL, e.g. https://dojo.example.com
    SECOPS_DEFECTDOJO_SECRET     secret name (default defectdojo_api_token)
    SECOPS_DEFECTDOJO_PAGE_SIZE  results per request (default 100)
    SECOPS_DEFECTDOJO_CA_BUNDLE  CA bundle for the API's certificate
    SECOPS_DEFECTDOJO_INSECURE   set to 1 to skip TLS verification (logged)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from functools import partial
from typing import Any

from ..common.http import with_retries
from ..common.watermark import comparable
from ..secrets import get_provider

log = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 100

#: Ordering key. Descending, so the newest modification is the first record
#: returned — see `fetch` for why that ordering is load-bearing.
ORDER_BY = "-last_status_update"


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

        while True:
            params = {
                "limit": self.page_size,
                "offset": offset,
                # `o`, not `ordering`. See the module docstring: the
                # conventional name is accepted and silently ignored.
                "o": ORDER_BY,
            }
            payload = with_retries(partial(self._get, creds, params))
            results = payload.get("results") or []
            if not results:
                return

            for record in results:
                mark = self.watermark_of(record)
                if floor is not None and mark is not None and comparable(mark) < floor:
                    # Descending order: everything after this is older still.
                    return
                yield record

            if not payload.get("next"):
                return
            offset += self.page_size

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
            json.dumps(record),
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
