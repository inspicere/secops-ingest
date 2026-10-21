"""KnowBe4 KSAT connector -- pulls training campaigns and enrollments via GraphQL.

Unlike the Cortex connectors, KSAT has no upstream aggregator; training and
simulation outcomes are collected directly from the KSAT GraphQL endpoint
(`training.knowbe4.com/graphql`, POST only, `Authorization: Bearer <token>`).

THIS SOURCE IS RE-READ EVERY RUN, NEVER TAILED ON A TIMESTAMP CURSOR.

Do not "optimise" this connector by adding a `dateRangeField: CREATED_AT` filter
wired to the stored watermark. Schema introspection on 2026-10-17 established
that the KSAT GraphQL API offers no mutation axis to resume from:

  * `enrollments` is the only collection-relevant query with a date-range
    filter, and its `dateRangeField` enum accepts only `CREATED_AT` and
    `COMPLETED_AT`.
  * An `Enrollment` object carries `updatedAt`, `startedAt`, `completedAt`, and
    `lastStartedAt`, but `updatedAt` is neither filterable nor sortable.
  * The sort enumerations carry no timestamp at all (`TrainingCampaignSortFields`
    is `name, percentComplete`; `PhishingCampaignSortFields` is `ID`).

An enrollment is created once (`NOT_STARTED`) and progresses to `IN_PROGRESS`
and `COMPLETED` days or weeks later. Filtering on `CREATED_AT >= cursor` while
advancing the cursor would read each enrollment once on the day it was created
and never see it finish -- the exact filter/sort axis mismatch that previously
shipped in another connector and silently dropped updates for weeks.

Instead, every run re-reads by scoping `trainingCampaigns` and `enrollments` by
campaign and status, and lands rows via the framework's upsert on
`(source_id, _event_time)` with `_event_time` pinned to the immutable
`createdAt` field. That is affordable here because campaigns are few,
enrollments are bounded by headcount, and the data changes slowly.

TWO FURTHER API CONSTRAINTS:

  1. KEYSET PAGING VIA `cursor: BigInt`, NEVER `page`. The vendor's published
     documentation mentions only `page` and `per_page`, warning that results stay
     in sequence only "as long as the reported data itself does not change".
     Introspection shows every list query also accepts `cursor: BigInt`, which
     is keyset pagination and stays stable under concurrent modification.
  2. 150-LINE QUERY COMPLEXITY CAP. The GraphQL endpoint rejects queries over
     150 lines of complexity (while vendor example queries run to ~300). Both
     queries request only the fields consumed by reporting and omit user PII
     (`email`, `firstName`, `lastName`).

Configuration:

    SECOPS_KSAT_SECRET             secret prefix to resolve (default ksat)
    SECOPS_KSAT_PAGE_SIZE          records per request (`per`, default 100, cap 500)
    SECOPS_KSAT_CAMPAIGN_STATUS    optional TrainingCampaignStatus filter
    SECOPS_KSAT_ENROLLMENT_STATUS  optional EnrollmentStatus filter
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
    KsatError,
    normalize_endpoint,
    resolve,
)

#: Re-exported so callers and tests import KSAT names from one place.
__all__ = [
    "ENROLLMENTS_QUERY",
    "PAGE_CAP",
    "SOURCE",
    "TRAINING_CAMPAIGNS_QUERY",
    "KsatCreds",
    "KsatError",
    "KsatSource",
    "normalize_endpoint",
    "resolve",
]

log = logging.getLogger(__name__)

#: `pagination.nextCursor`. Introspected against the live schema 2026-10-20.
#:
#: Pages on `page`, not `cursor`: measured on the live API, every
#: collection accepts `cursor: BigInt` and never populates nextCursor, so
#: keyset paging silently stops after page one. See _paginate.
#:
#: `statuses` is a LIST, and null means "every status" -- the six are CREATED,
#: ENROLLING, IN_PROGRESS, CLOSED, COMPLETED and TESTMODE. TESTMODE campaigns
#: are real campaigns in test mode; a deployment that reports on completion
#: rates probably wants them excluded, which is why the filter is exposed
#: rather than hard-coded.
TRAINING_CAMPAIGNS_QUERY = """\
query TrainingCampaigns(
  $statuses: [TrainingCampaignStatuses!]
  $per: Int!
  $page: Int!
) {
  trainingCampaigns(statuses: $statuses, per: $per, page: $page) {
    nodes {
      id
      name
      status
      startsAt
      endsAt
      percentComplete
    }
    pagination {
      page
      pages
      per
      totalCount
    }
  }
}"""

#: 23 lines -- requests only outcome fields and an opaque user id/status pair,
#: omitting PII (email, firstName, lastName) and staying well under the 150-line cap.
ENROLLMENTS_QUERY = """\
query Enrollments(
  $trainingCampaignId: Int!
  $status: EnrollmentStatuses
  $per: Int!
  $page: Int!
) {
  enrollments(
    trainingCampaignId: $trainingCampaignId
    status: $status
    per: $per
    page: $page
  ) {
    nodes {
      id
      status
      createdAt
      updatedAt
      startedAt
      completedAt
      lastStartedAt
      timeSpentInSeconds
      score
      policyAcknowledged
      user {
        id
        archived
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


#: At most this many errors summarised. A rejected query yields one error per
#: offending field; six was the real count on the first live run.

class KsatSource:
    name = "ksat"
    table = "raw_ksat.enrollments"

    def __init__(
        self,
        *,
        secret: str | None = None,
        page_size: int | None = None,
        campaign_status: str | None = None,
        enrollment_status: str | None = None,
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
        self.campaign_status = (
            campaign_status
            if campaign_status is not None
            else (os.environ.get("SECOPS_KSAT_CAMPAIGN_STATUS") or None)
        )
        self.enrollment_status = (
            enrollment_status
            if enrollment_status is not None
            else (os.environ.get("SECOPS_KSAT_ENROLLMENT_STATUS") or None)
        )
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

    # -- fetching -----------------------------------------------------------

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield enrollments scoped by training campaign and status.

        `cursor` is deliberately unused for filtering: KSAT has no filterable or
        sortable modification timestamp, and filtering on `CREATED_AT` would drop
        every status transition (`NOT_STARTED -> IN_PROGRESS -> COMPLETED`) that
        occurs after the run in which an enrollment was created.
        """
        active_creds = creds if isinstance(creds, KsatCreds) else self._creds
        if active_creds is None:
            active_creds = self.authenticate()

        campaigns = list(
            self._client.paginate(
                active_creds,
                TRAINING_CAMPAIGNS_QUERY,
                "trainingCampaigns",
                # statuses is a list; None means every status.
                {
                    "statuses": (
                        [self.campaign_status] if self.campaign_status else None
                    )
                },
            )
        )
        if not campaigns:
            # "Nothing to do" and "pointed at the wrong tenant" are
            # indistinguishable from outside when both yield SUCCESS with zero
            # rows. Measured on a real Diamond-tier tenant: zero campaigns
            # across all six statuses, because its training lives in another
            # LMS entirely. Say so once per run rather than let a dashboard
            # show a healthy connector delivering nothing.
            log.warning(
                "ksat: no training campaign%s returned; this source will land "
                "no rows. Either this tenant runs no KSAT training, or "
                "SECOPS_KSAT_CAMPAIGN_STATUS excludes everything it has.",
                "s" if self.campaign_status is None else f"s with status {self.campaign_status}",
            )
        else:
            log.info("ksat: fetched %d training campaign(s)", len(campaigns))

        for campaign in campaigns:
            if (
                self.campaign_status is not None
                and campaign.get("status") != self.campaign_status
            ):
                continue
            campaign_id = int(campaign["id"])
            for enrollment in self._client.paginate(
                active_creds,
                ENROLLMENTS_QUERY,
                "enrollments",
                {"trainingCampaignId": campaign_id, "status": self.enrollment_status},
            ):
                record = dict(enrollment)
                record.setdefault("campaign", campaign)
                yield record

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map an enrollment to `(source_id, payload, _event_time, _source_run_id)`.

        `_event_time` is `createdAt`, which is immutable across the enrollment's
        lifecycle (`NOT_STARTED -> IN_PROGRESS -> COMPLETED`). Keying the upsert
        on `(source_id, createdAt)` ensures that when a re-read sees an
        enrollment change status, PostgreSQL updates the existing row in place
        instead of inserting a duplicate into a new partition.
        """
        source_id = str(record["id"])
        return (
            source_id,
            to_json(record, identifier=source_id),
            record["createdAt"],
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        """Return the enrollment's latest mutation time (`updatedAt` or `createdAt`).

        Even though `fetch()` ignores the stored watermark and re-reads every
        run, returning `record.get("updatedAt") or record["createdAt"]`:
          1. Lets `common.run.execute()` record a row in `control.ingest_watermark`
             (whereas returning `None` leaves `high_watermark` as `None` and
             writes nothing to `control.ingest_watermark`).
          2. Gives `common.watermark.comparable()` a valid ISO-8601 timestamp
             that orders cleanly as a `datetime` without falling back to string
             ordering.
          3. Records two distinct facts in `control.ingest_watermark`:
             `updated_at` is when the last full re-read succeeded, and
             `cursor_value` is the freshest enrollment mutation observed in it.
        """
        return record.get("updatedAt") or record["createdAt"]


SOURCE = KsatSource()
