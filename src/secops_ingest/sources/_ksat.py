"""Shared KSAT GraphQL client: credentials, paging and error handling.

Separate from the sources that use it, the way _cortex.py serves xdr and
xsoar. Two KSAT sources exist -- training enrollments and phishing simulation
results -- and both need the same endpoint normalisation, the same page walk
and, above all, the same error handling: KSAT answers a malformed query with
HTTP 200 and an `errors` array, so a client that does not inspect it reports
success on a query the server rejected.
"""

from __future__ import annotations

import logging
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
from ..redaction import register_secret
from ..secrets import get_provider

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



class KsatClient:
    """Posts GraphQL to KSAT and walks its pages.

    Holds only transport concerns. What to ask for, and what to do with the
    records, belongs to the source.
    """

    def __init__(
        self,
        *,
        page_size: int,
        transport: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = 5,
        page_walk_cap: int = PAGE_WALK_CAP,
    ) -> None:
        self.page_size = page_size
        self._transport = transport
        self._sleep = sleep
        self._attempts = attempts
        # Injectable so a test can bound the walk without mutating a module
        # global -- the cap is reached only by a server that reports no `pages`
        # and never short-pages, which is a hang rather than an error.
        self.page_walk_cap = page_walk_cap

    def paginate(
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
            payload = self.call_graphql(creds, query, variables)
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
            if page >= self.page_walk_cap:
                log.warning(
                    "ksat %s stopped at the %d-page cap with %d record(s) "
                    "collected; the collection may be incomplete",
                    root_field,
                    self.page_walk_cap,
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

    def call_graphql(
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

