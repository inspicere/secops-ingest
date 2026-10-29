"""Wazuh connector — pulls alerts from the Wazuh indexer.

Wazuh is an open-source (GPLv2) XDR/SIEM platform. This connector exists as the
worked example against a real product rather than a synthetic one: it talks to
software anyone can stand up, so the framework's behaviour can be checked
end-to-end without a commercial licence.

Speaking HTTP to a GPL-licensed server places no licence obligation on this
Apache-2.0 client. Nothing here links to or vendors Wazuh code.

    python -m secops_ingest wazuh

Reads the **indexer** API, not the manager API on :55000. The manager API is for
managing agents and configuration; alerts live in the indexer. Aiming at the
wrong one is the usual first wrong turn.

Configuration (endpoints and tenancy are config, never constants):

    SECOPS_WAZUH_URL           indexer base URL, e.g. https://127.0.0.1:9200
    SECOPS_WAZUH_INDEX         index pattern           (default wazuh-alerts-*)
    SECOPS_WAZUH_USER          indexer username        (default admin; logged as
                               DEGRADED every run -- use a read-only user)
    SECOPS_WAZUH_SECRET        secret name to resolve  (default wazuh_indexer_password)
    SECOPS_WAZUH_CA_BUNDLE     path to a CA bundle for the indexer's certificate;
                               verification against it is never relaxed
    SECOPS_WAZUH_INSECURE      set to 1 to skip TLS verification (logged, loudly);
                               ignored when SECOPS_WAZUH_CA_BUNDLE is set
    SECOPS_WAZUH_LAG_SECONDS   late-arrival overlap    (default 900)
    SECOPS_WAZUH_PAGE_SIZE     hits per request        (default 500)
"""

from __future__ import annotations

import logging
import os
import ssl
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from functools import partial
from typing import Any

from ..common.http import RetryableResponse, with_retries
from ..common.payload import to_json
from ..secrets import get_provider

log = logging.getLogger(__name__)

DEFAULT_INDEX = "wazuh-alerts-*"
DEFAULT_LAG_SECONDS = 900
DEFAULT_PAGE_SIZE = 500

#: The account the indexer is installed with. It holds every privilege the
#: cluster has, including writes to the security index, so a leaked copy of
#: the ingest's credential is a leaked copy of the whole SIEM. Still the
#: default so that an existing deployment keeps running; the warning below is
#: what keeps it from being forgotten.
SUPERUSER = "admin"


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


class WazuhSource:
    name = "wazuh"
    table = "raw_wazuh.alerts"

    #: Keyset paging on `search_after` over an ascending `timestamp` sort, and
    #: `timestamp` is also the watermark. Same field, same direction, so the
    #: highest mark seen really does mean everything below it has been read.
    fetch_order_is_watermark_order = True

    def __init__(self) -> None:
        self.url = (os.environ.get("SECOPS_WAZUH_URL") or "").rstrip("/")
        self.index = os.environ.get("SECOPS_WAZUH_INDEX", DEFAULT_INDEX)
        self.user = os.environ.get("SECOPS_WAZUH_USER", SUPERUSER)
        self.secret_name = os.environ.get("SECOPS_WAZUH_SECRET", "wazuh_indexer_password")
        self.lag_seconds = _env_int("SECOPS_WAZUH_LAG_SECONDS", DEFAULT_LAG_SECONDS)
        self.page_size = _env_int("SECOPS_WAZUH_PAGE_SIZE", DEFAULT_PAGE_SIZE)
        # Resolved once per run by authenticate(); None means not yet resolved
        # (False is a real answer: verification off).
        self._verify: Any = None

    # -- credentials --------------------------------------------------------

    def authenticate(self) -> Any:
        if not self.url:
            raise ValueError("SECOPS_WAZUH_URL is not set")
        # Before the password is fetched, so that a CA bundle that cannot be
        # loaded fails the run here, with its path named, rather than on the
        # first request -- and so that its warnings appear once per run, not
        # once per page.
        self._verify = self._tls_verify()
        if self.user == SUPERUSER:
            # Dim, not dark: the run proceeds, because refusing would stop
            # alert ingest on every host that has not created the read-only
            # user yet. But it must not look like a healthy run either.
            log.warning(
                "DEGRADED: reading the Wazuh indexer as its superuser %r, which can "
                "also write and administer the cluster. Create a user limited to "
                "read on %s and set SECOPS_WAZUH_USER/SECOPS_WAZUH_SECRET to it.",
                self.user, self.index,
            )
        password = get_provider().get(self.secret_name)
        # Registered so that a traceback or a debug-level httpx log cannot spill
        # it. The redaction filter is a backstop, not permission to log it.
        from ..redaction import register_secret

        register_secret(password)
        return (self.user, password)

    # -- fetching -----------------------------------------------------------

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield alerts at or after `cursor`, minus a late-arrival overlap.

        Wazuh alerts are append-only: nothing rewrites one after it is indexed,
        so unlike vendors that mutate records there is no separate "updated"
        field, and the event time doubles as the watermark.

        That is exactly what makes late arrival dangerous here. An agent that
        was offline, or a manager under load, can index an alert whose
        timestamp is older than a watermark we have already advanced past. A
        strict `> cursor` query would step over it and never look back, and the
        alert would be lost silently — the failure would look like nothing at
        all.

        So each run re-reads a trailing window. Re-reading is free because
        landing is an upsert keyed on (source_id, _event_time): a row seen twice
        updates itself. The overlap trades a little duplicate work for not
        losing alerts, which is the right way round.
        """
        since = self._since(cursor)
        search_after: list[Any] | None = None
        page = 0

        while True:
            body = self._query(since, search_after)
            # partial, not a lambda: a lambda would close over the loop
            # variable, which is safe only because with_retries happens to call
            # it immediately -- not a property worth depending on.
            started = time.monotonic()
            resp = with_retries(partial(self._search, creds, body))
            hits = resp.get("hits", {}).get("hits", [])
            log.info("page %d: %d hits in %.1fs", page, len(hits), time.monotonic() - started)
            if not hits:
                return

            for hit in hits:
                record = dict(hit.get("_source") or {})
                # Prefer the alert's own id. `_id` is the indexer's key and is
                # stable, but it is the fallback: two indices could in principle
                # hold the same alert, and the alert id is what identifies it.
                record.setdefault("id", hit.get("_id"))
                yield record

            page += 1
            if len(hits) < self.page_size:
                return
            search_after = hits[-1].get("sort")
            if not search_after:
                # Without a sort key there is no way to continue deterministically.
                # Stopping loses the tail of this run; the watermark still
                # advanced over what was yielded, and the overlap picks the rest
                # up next run. Guessing an offset would silently skip or repeat.
                log.warning("no sort key on the last hit; ending run after %d pages", page)
                return

    def _since(self, cursor: str | None) -> str | None:
        if not cursor:
            return None
        try:
            ts = datetime.fromisoformat(str(cursor))
        except ValueError:
            # A watermark we cannot parse must not silently become "everything".
            # A full re-read of a large index is a self-inflicted outage.
            raise ValueError(f"watermark is not an ISO-8601 timestamp: {cursor!r}") from None
        return (ts - timedelta(seconds=self.lag_seconds)).isoformat()

    def _query(self, since: str | None, search_after: list[Any] | None) -> dict[str, Any]:
        query: dict[str, Any] = (
            {"range": {"timestamp": {"gte": since}}} if since else {"match_all": {}}
        )
        body: dict[str, Any] = {
            "size": self.page_size,
            "query": query,
            # A total order is required. Sorting on timestamp alone repeats or
            # skips rows whenever two alerts share a millisecond, which at any
            # real volume is constantly.
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
        }
        if search_after:
            body["search_after"] = search_after
        return body

    def _search(self, creds: Any, body: dict[str, Any]) -> dict[str, Any]:
        """One `_search` call. Separated so tests can drive fetch() offline."""
        import httpx

        resp = httpx.post(
            f"{self.url}/{self.index}/_search",
            json=body,
            auth=creds,
            verify=self._verify if self._verify is not None else self._tls_verify(),
            timeout=60.0,
        )
        resp.raise_for_status()
        payload = dict(resp.json())
        # A 200 is not a complete answer. OpenSearch serves what the healthy
        # shards hold when others fail or the search times out, and says so
        # only in the body. Landing that page and moving search_after past it
        # advances this ORDERED source's watermark beyond alerts that were
        # never returned -- further than the lag overlap ever looks back. So a
        # partial answer is retried like a 503 and, if it persists, fails the
        # run with the watermark where it was.
        shards = payload.get("_shards") or {}
        failed = shards.get("failed") or 0
        if payload.get("timed_out") or (isinstance(failed, int) and failed > 0):
            raise RetryableResponse(
                f"partial result: {failed} of {shards.get('total', '?')} shard(s) "
                f"failed, timed_out={bool(payload.get('timed_out'))}"
            )
        return payload

    def _tls_verify(self) -> Any:
        bundle = os.environ.get("SECOPS_WAZUH_CA_BUNDLE")
        insecure = os.environ.get("SECOPS_WAZUH_INSECURE") == "1"
        if bundle:
            if insecure:
                # Verification wins. Both set is the half-finished state of a
                # CA roll-out, and the stale opt-out must not quietly become
                # live again if the bundle setting is later removed.
                log.warning(
                    "SECOPS_WAZUH_INSECURE=1 is IGNORED because SECOPS_WAZUH_CA_BUNDLE "
                    "is set; the indexer is verified. Remove SECOPS_WAZUH_INSECURE."
                )
            return self._ca_context(bundle)
        if insecure:
            # Wazuh generates its own CA at install, so an operator without the
            # bundle to hand will reach for this. Say so every run: a silent
            # opt-out becomes permanent, and this one removes the only defence
            # against an intercepted credential.
            log.warning(
                "DEGRADED: TLS verification DISABLED for the Wazuh indexer "
                "(SECOPS_WAZUH_INSECURE=1). Set SECOPS_WAZUH_CA_BUNDLE instead."
            )
            return False
        return True

    @staticmethod
    def _ca_context(bundle: str) -> ssl.SSLContext:
        """A verifying context anchored on `bundle`, and only on it.

        A context rather than the path: httpx deprecates a path for `verify`,
        and loading it here turns a missing or unparsable bundle into an error
        that names the setting, instead of a handshake failure pages later.
        Hostname checking and CERT_REQUIRED are the defaults and stay on. There
        is no fallback to an unverified connection: a bundle that cannot be
        used is a configuration error, and the run fails with the watermark
        where it was.
        """
        try:
            return ssl.create_default_context(cafile=bundle)
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(
                f"SECOPS_WAZUH_CA_BUNDLE={bundle!r} could not be loaded ({exc}); "
                "refusing to connect to the indexer without verifying it"
            ) from None

    # -- landing ------------------------------------------------------------

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return (
            record["id"],
            to_json(record, identifier=record["id"]),
            record["timestamp"],
            run_id or None,
        )

    def watermark_of(self, record: dict[str, Any]) -> Any:
        return record["timestamp"]


SOURCE = WazuhSource()
