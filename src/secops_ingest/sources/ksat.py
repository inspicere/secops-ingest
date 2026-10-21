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
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import partial
from typing import Any
from urllib.parse import urlsplit

import httpx

from .. import redaction
from ..common.http import RETRYABLE_STATUS, RetryBudgetExhausted, with_retries
from ..common.payload import to_json
from ..redaction import register_secret
from ..secrets import get_provider
from ._cortex import env_int

log = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 100
PAGE_CAP = 500
DEFAULT_TIMEOUT = 60.0

#: Hard bound on a page walk. 325 pages was the largest `pages` value
#: measured (650 users at per=2); at the default page size a real
#: collection is far smaller, so this only catches a server that keeps
#: serving pages forever.
PAGE_WALK_CAP = 2000

#: 15 lines -- well below the 150-line GraphQL complexity cap.
#:
#: EVERY NAME HERE IS MEASURED, not inferred. The first version of this query
#: was written from notes and returned six GraphQL errors on its first live
#: call -- `status` instead of `statuses`, `TrainingCampaignStatus` instead of
#: `TrainingCampaignStatuses`, `startDate`/`endDate` instead of
#: `startsAt`/`endsAt`, and `pagination.cursor` instead of
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
_MAX_ERRORS = 6

#: "(Did you mean `startsAt`?)" / "Did you mean `a`, `b` or `c`" -- the
#: vendor's own correction, and the single most useful token in the response.
_SUGGESTION_RE = re.compile(r"[Dd]id you mean ([^)?.]+)")
_IDENT_RE = re.compile(r"[`'\"]([A-Za-z_][A-Za-z0-9_]{0,60})[`'\"]")


def _error_summary(errors: Any) -> str:
    """Summarise GraphQL errors as code + location + the vendor's suggestion.

    STRUCTURE, NOT FREE TEXT, and that distinction is the whole design. This
    used to report only a count, so the first live run failed with
    "KSAT GraphQL query failed (6 error(s))" while the response body held six
    messages each naming the offending field AND the correct one. Recovering
    that cost a deploy cycle and a live probe against the vendor.

    But the raw `message` cannot be echoed: a vendor is free to put anything in
    it, and a test in this suite proves the point by returning a message
    containing the bearer token, the endpoint path and the whole query. So this
    takes only:

      * `extensions.code` -- a fixed vocabulary (undefinedField,
        argumentNotAccepted, variableRequiresValidType, variableNotUsed).
      * the LAST element of `path` -- the offending leaf, e.g. `startDate`.
        Not the whole path, which carries the operation name.
      * identifiers inside the "did you mean" clause -- the correction, which
        by construction is a name our query does NOT yet use.

    Anything containing a slash or a dot is dropped, so hostnames and paths
    cannot ride along, and every part is scrubbed through the redaction
    registry so the token is masked even if a vendor echoed it.
    """
    if not isinstance(errors, list):
        return "1 error (unparseable error payload)"

    lines: list[str] = []
    for err in errors[:_MAX_ERRORS]:
        if not isinstance(err, dict):
            continue
        code = str((err.get("extensions") or {}).get("code") or "error")
        message = redaction.scrub(str(err.get("message") or ""))

        path = err.get("path")
        leaf = ""
        if isinstance(path, list) and path:
            candidate = str(path[-1])
            if "/" not in candidate and "." not in candidate and len(candidate) <= 60:
                leaf = candidate

        suggestion = ""
        found = _SUGGESTION_RE.search(message)
        if found:
            names = [
                n for n in _IDENT_RE.findall(found.group(1))
                if "/" not in n and "." not in n
            ][:4]
            if names:
                suggestion = " (did you mean: " + ", ".join(names) + ")"

        lines.append(f"{code}" + (f" at {leaf}" if leaf else "") + suggestion)

    more = len(errors) - len(lines)
    summary = f"{len(errors)} error(s): " + "; ".join(lines or ["(no detail)"])
    return summary + (f" (+{more} more)" if more > 0 else "")


class KsatError(RuntimeError):
    """Raised on KSAT configuration, transport, HTTP, or GraphQL errors.

    Messages intentionally exclude the bearer token, the endpoint URL/path, and
    the GraphQL query text so that `control.ingest_run.error_summary` and logs
    cannot leak credentials or internal schema details.
    """


@dataclass(frozen=True)
class KsatCreds:
    """Resolved KSAT bearer token and normalised GraphQL endpoint."""

    api_key: str
    endpoint: str

    def __repr__(self) -> str:
        return "KsatCreds(***REDACTED***)"

    def __str__(self) -> str:
        return "KsatCreds(***REDACTED***)"


def normalize_endpoint(raw_url: str) -> tuple[str, str]:
    """Normalise a stored `base_url` into `(https_endpoint, host)`.

    Vault stores `training.knowbe4.com/graphql` (no scheme, path already
    included), whereas Cortex secrets store a bare host with a scheme. This
    accepts either shape, enforces HTTPS, and guarantees a single `/graphql`
    suffix without echoing the input URL into any error message.
    """
    cleaned = raw_url.strip().rstrip("/")
    if not cleaned:
        raise KsatError("ksat base_url must not be empty")

    if "://" in cleaned:
        parts = urlsplit(cleaned)
        scheme = parts.scheme.lower()
        if scheme != "https":
            raise KsatError(f"ksat base_url must use https://, got scheme {scheme!r}")
    else:
        if cleaned.lower().startswith("http:"):
            raise KsatError("ksat base_url must use https://")
        parts = urlsplit(f"https://{cleaned}")

    host = parts.netloc.strip()
    if not host:
        raise KsatError("ksat base_url has no host")

    path = parts.path.rstrip("/")
    if not path:
        path = "/graphql"
    elif not path.endswith("/graphql"):
        path = f"{path}/graphql"

    return f"https://{host}{path}", host


def resolve(secret: str) -> KsatCreds:
    """Resolve `<secret>.base_url` and `<secret>.api_key` and register both for redaction."""
    provider = get_provider()
    raw_url = provider.get(f"{secret}.base_url")
    raw_key = provider.get(f"{secret}.api_key")

    api_key = raw_key.strip()
    if not api_key:
        raise KsatError("ksat api_key must not be empty")

    # Register the 310-character JWT immediately so RedactingFilter and scrub()
    # catch it if any third-party frame ever formats it.
    register_secret(api_key)

    endpoint, host = normalize_endpoint(raw_url)
    register_secret(host)
    register_secret(endpoint)
    return KsatCreds(api_key=api_key, endpoint=endpoint)


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
        self._transport = transport
        self._sleep = sleep
        self._attempts = attempts
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
            self._paginate(
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
            for enrollment in self._paginate(
                active_creds,
                ENROLLMENTS_QUERY,
                "enrollments",
                {"trainingCampaignId": campaign_id, "status": self.enrollment_status},
            ):
                record = dict(enrollment)
                record.setdefault("campaign", campaign)
                yield record

    def _paginate(
        self,
        creds: KsatCreds,
        query: str,
        root_field: str,
        base_variables: dict[str, Any],
    ) -> Iterator[dict[str, Any]]:
        """Walk a GraphQL list query with `page`, and check the walk was complete.

        PAGE, NOT CURSOR, and this is measured rather than preferred. Every
        collection on the live API accepts `cursor: BigInt` and never populates
        `pagination.nextCursor`, so keyset paging stops after the first page
        and the run reports success. Measured 2026-10-20: 2 of 650 users, 25 of
        117 phishing runs, 100 of 648 recipients.

        The vendor warns that page ordering holds only "as long as the reported
        data itself does not change", and that warning is real -- but it
        describes DUPLICATES and REORDERING, which an upsert absorbs. Cursor's
        failure here is silent TRUNCATION, which nothing absorbs. So: page,
        plus the completeness check below, which turns a short read into a
        warning at the moment it happens rather than a row count nobody
        queries months later.
        """
        page = 1
        collected = 0
        total_count: int | None = None
        pages: int | None = None

        while True:
            variables = {**base_variables, "per": self.page_size, "page": page}
            started = time.monotonic()
            payload = self._call_graphql(creds, query, variables)
            data = payload.get("data")
            if not isinstance(data, dict):
                raise KsatError("KSAT GraphQL response missing data block")
            block = data.get(root_field) or {}
            if not isinstance(block, dict):
                raise KsatError("KSAT GraphQL response field is not an object")

            nodes = block.get("nodes") or []
            pagination = block.get("pagination") or {}
            if isinstance(pagination, dict):
                if isinstance(pagination.get("totalCount"), int):
                    total_count = pagination["totalCount"]
                if isinstance(pagination.get("pages"), int):
                    pages = pagination["pages"]

            log.info(
                "ksat %s page=%s: %d record(s) in %.1fs",
                root_field,
                page,
                len(nodes),
                time.monotonic() - started,
            )

            for node in nodes:
                collected += 1
                yield dict(node)

            if not nodes:
                break
            # Three terminators, most authoritative first:
            #   1. `pages`, when the API reports it -- it always did in
            #      measurement, on every collection.
            #   2. a SHORT page: fewer nodes than asked for means the last one.
            #      Without this, a server that omits `pages` and keeps serving
            #      the same page walks to the cap -- which is a hang, not an
            #      error, and nested walks multiply it.
            #   3. the cap, for a server that does neither.
            if pages is not None and page >= pages:
                break
            if len(nodes) < self.page_size:
                break
            if page >= PAGE_WALK_CAP:
                log.warning(
                    "ksat %s stopped at the %d-page cap with %d record(s) "
                    "collected; the collection may be incomplete",
                    root_field,
                    PAGE_WALK_CAP,
                    collected,
                )
                break
            page += 1

        if total_count is not None and collected < total_count:
            log.warning(
                "ksat %s collected %d of %d record(s) the API reported; "
                "the walk was short and this run is incomplete",
                root_field,
                collected,
                total_count,
            )

    def _call_graphql(
        self,
        creds: KsatCreds,
        query: str,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute one GraphQL request under `with_retries`, scrubbing error context."""
        try:
            return with_retries(
                partial(self._graphql, creds, query, variables),
                attempts=self._attempts,
                sleep=self._sleep,
            )
        except KsatError:
            raise
        except RetryBudgetExhausted as exc:
            cause = exc.__cause__
            if isinstance(cause, httpx.HTTPStatusError):
                code = cause.response.status_code
                raise KsatError(
                    f"KSAT API request failed after {self._attempts} attempts (HTTP {code})"
                ) from None
            raise KsatError(
                f"KSAT API request failed after {self._attempts} attempts"
            ) from None

    def _graphql(
        self,
        creds: KsatCreds,
        query: str,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        """Perform a single GraphQL POST.

        Uses an explicit status check rather than `response.raise_for_status()`
        because httpx's default HTTPStatusError message embeds the full request
        URL (including `/graphql`). Underlying transport errors are re-wrapped
        without their original message or request URL so `with_retries` can
        still retry them without carrying the endpoint path or headers.
        """
        headers = {
            "Authorization": f"Bearer {creds.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = {"query": query, "variables": variables}

        try:
            with httpx.Client(transport=self._transport, timeout=DEFAULT_TIMEOUT) as client:
                response = client.post(creds.endpoint, json=body, headers=headers)
        except httpx.TimeoutException:
            raise httpx.TimeoutException("KSAT API request timed out") from None
        except httpx.TransportError:
            raise httpx.TransportError("KSAT API transport error") from None
        except httpx.HTTPError:
            raise KsatError("KSAT API HTTP error") from None

        if response.status_code in RETRYABLE_STATUS:
            raise httpx.HTTPStatusError(
                f"KSAT API returned HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        if response.status_code >= 400:
            raise KsatError(f"KSAT API returned HTTP {response.status_code}")

        try:
            decoded = response.json()
        except ValueError:
            raise KsatError("KSAT API returned invalid JSON") from None

        if not isinstance(decoded, dict):
            raise KsatError("KSAT API returned a non-object JSON payload")

        errors = decoded.get("errors")
        if errors:
            raise KsatError(f"KSAT GraphQL query failed: {_error_summary(errors)}")

        return decoded

    # -- landing ------------------------------------------------------------

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
