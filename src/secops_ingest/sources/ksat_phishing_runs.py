"""KSAT phishing simulation runs -- one row per run, with its outcome rates.

A run is one send of one phishing campaign to a group of people. Its aggregate
rates -- phishPronePercentage and reportedPercentage -- are the numbers a
security-awareness dashboard actually shows, and they are the reason this
source exists as well as the per-recipient one.

THIS SOURCE IS RE-READ IN FULL EVERY RUN, and unlike the training connector
that is cheap rather than merely necessary. Measured 2026-10-20: 117 runs
across 19 campaigns, which is 3 requests at the default page size. The whole
collection costs less than a single page of recipients.

Re-reading is also what keeps the rates correct. A recipient can act long
after the run closes -- measured, 4 of 952 recipients mutated after their run's
completedAt, the worst 75 days later -- and each of those moves the run's
aggregate. A run-level cursor would have frozen the rate at whatever it was on
the day the run ended.

PAGES ON `page`, NOT `cursor`. Every collection on this API accepts
`cursor: BigInt` and never populates `pagination.nextCursor`: a cursor walk
reaches 25 of these 117 runs and reports success. See _ksat.KsatClient.paginate.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator
from typing import Any

from ..common.payload import to_json
from ..redaction import register_secret
from ._cortex import env_int
from ._ksat import (
    DEFAULT_PAGE_SIZE,
    PAGE_CAP,
    KsatClient,
    KsatCreds,
    resolve,
)

log = logging.getLogger(__name__)

__all__ = ["PHISHING_RUNS_QUERY", "SOURCE", "KsatPhishingRunsSource"]

#: 19 lines, far under the 150-line complexity cap.
#:
#: Every name measured against the live schema before this module existed.
#: `sortField: started_at` is the only sort the API offers on runs, and it is
#: used for stability rather than for resuming: new runs append at the end, so
#: an ascending walk keeps earlier pages stable while it is in flight. The
#: vendor warns page ordering holds only while the data does not change, and
#: appending at the end is the one ordering that makes that warning harmless.
#:
#: NO PII. campaign.name is a campaign label, not a person. The per-recipient
#: source carries user ids, and no email addresses, for the same reason.
PHISHING_RUNS_QUERY = """\
query PhishingRuns($per: Int!, $page: Int!) {
  phishingCampaignRuns(
    per: $per
    page: $page
    sortField: started_at
    sortDirection: ASCENDING
  ) {
    nodes {
      id
      status
      createdAt
      startedAt
      completedAt
      duration
      recipientCount
      scheduledCount
      phishPronePercentage
      reportedPercentage
      campaign {
        id
        name
        campaignType
      }
    }
    pagination {
      page
      pages
      per
      totalCount
    }
  }
}"""


class KsatPhishingRunsSource:
    """Lands every phishing campaign run, re-read in full each time."""

    name = "ksat_phishing_runs"
    table = "raw_ksat.phishing_runs"

    def __init__(
        self,
        *,
        secret: str | None = None,
        page_size: int | None = None,
        transport: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = 5,
        page_walk_cap: int | None = None,
    ) -> None:
        self.secret = secret or os.environ.get("SECOPS_KSAT_SECRET", "ksat")
        raw_size = (
            page_size
            if page_size is not None
            else env_int("SECOPS_KSAT_PAGE_SIZE", DEFAULT_PAGE_SIZE)
        )
        self.page_size = min(max(raw_size, 1), PAGE_CAP)
        self._client = KsatClient(
            page_size=self.page_size,
            transport=transport,
            sleep=sleep,
            attempts=attempts,
            **({} if page_walk_cap is None else {"page_walk_cap": page_walk_cap}),
        )
        self._creds: KsatCreds | None = None

    # -- credentials --------------------------------------------------------

    def authenticate(self, creds: Any = None) -> KsatCreds:
        if isinstance(creds, KsatCreds):
            register_secret(creds.api_key)
            self._creds = creds
            return creds
        self._creds = resolve(self.secret)
        return self._creds

    # -- collection ---------------------------------------------------------

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield every run. `cursor` is ignored, deliberately.

        There is no run-level axis worth resuming from: a run's rates keep
        moving after it closes, so a cursor would read each run once and never
        see its final numbers. The framework still records a watermark, which
        says when the last complete re-read happened.
        """
        client = creds if isinstance(creds, KsatCreds) else self.authenticate(creds)
        yielded = 0
        for node in self._client.paginate(
            client, PHISHING_RUNS_QUERY, "phishingCampaignRuns", {}
        ):
            yielded += 1
            yield node
        if not yielded:
            log.warning(
                "ksat_phishing_runs: no runs returned; this source will land no "
                "rows. Either this tenant runs no phishing simulations, or the "
                "credential cannot see them."
            )

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map a run to `(source_id, payload, _event_time, _source_run_id)`.

        `_event_time` is `createdAt`, the one timestamp on a run that does not
        move: status, completedAt and both rates all change as recipients act.
        Keying the upsert on `(source_id, createdAt)` means a re-read refreshes
        the row in place instead of inserting a second one under a new
        partition.
        """
        return (
            str(record["id"]),
            to_json(record),
            record["createdAt"],
            run_id,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        """The latest time this run actually carries.

        completedAt, else startedAt, else createdAt. An ERRORed run has a
        completedAt and NO startedAt -- measured on run 18223589 -- so the
        order matters and a plain `startedAt` would return None for it.
        """
        return (
            record.get("completedAt")
            or record.get("startedAt")
            or record["createdAt"]
        )


SOURCE = KsatPhishingRunsSource()
