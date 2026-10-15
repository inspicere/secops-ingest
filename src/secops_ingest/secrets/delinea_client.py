# src/secops_ingest/secrets/delinea_client.py
"""A minimal Secret Server client, written rather than depended upon.

WHY NOT python-tss-sdk. It adds its 300-second clock drift instead of
subtracting it (delinea/secrets/server.py:272-278), so it presents an expired
token for up to five minutes and has no 401 retry; the comparison also uses
naive local time. It offers no single-field retrieval, no autoComment, and is
CI-tested only to Python 3.11. See docs/research/2026-10-14-delinea/ in the
metabase_security repo. This file is the part of it we actually need.

THREE DELIBERATE CHOICES IN ONE URL:

    GET /api/v1/secrets/{id}/fields/{slug}?noAutoCheckout=true&autoComment={run}

  * the single-field endpoint keeps blast radius to one field rather than a
    whole secret, and keeps the audit record specific;
  * noAutoCheckout=true, because a plain GET on a checkout-enabled secret can
    check it out to this account, block other consumers, and trigger rotation
    on check-in -- a scheduled read that silently rotates somebody else's
    credential is the worst failure available here;
  * autoComment carries the run id into Secret Server's own access audit
    record, which is where attributable audit comes from.

Addressing is by numeric id. `secretPath` on the single-field endpoint is
undocumented upstream and no vendor code attempts it, so it is treated as
unsupported until measured.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .base import SecretError, SecretNotFound
from .secret import Secret

#: Replace a token this many seconds before it expires. SUBTRACTED, unlike
#: upstream. 300s is comfortably more than any single request takes.
DRIFT_SECONDS = 300.0
_TIMEOUT = 30.0


class SecretServerClient:
    """Fetch single fields from Delinea Secret Server."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: Secret,
        run_id: str = "",
        transport: Any | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on extra
            raise SecretError(
                "the Delinea provider requires the 'http' extra: "
                "pip install secops-ingest[http]"
            ) from exc
        if not isinstance(client_secret, Secret):
            raise SecretError("client_secret must be a Secret, not a bare string")
        self._client = httpx.Client(
            transport=transport, base_url=base_url.rstrip("/"), timeout=_TIMEOUT
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._run_id = run_id
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    # -- authentication -----------------------------------------------------

    def _authenticate(self) -> str:
        """Exchange the bootstrap credential for a bearer token."""
        import httpx

        try:
            response = self._client.post(
                "/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret.reveal(),
                },
            )
        except httpx.HTTPError as exc:
            raise SecretError("secret server unreachable during authentication") from exc
        if response.status_code >= 400:
            # The body can echo the client_secret back. Never include it.
            raise SecretError(
                f"secret server returned {response.status_code} during authentication"
            )
        body = response.json()
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise SecretError("secret server returned no access_token")
        expires_in = float(body.get("expires_in") or 0)
        self._token = token
        self._expires_at = self._clock() + max(expires_in - DRIFT_SECONDS, 0.0)
        return token

    def _bearer(self) -> str:
        if self._token is None or self._clock() >= self._expires_at:
            return self._authenticate()
        return self._token

    # -- retrieval ----------------------------------------------------------

    def field(self, secret_id: str, slug: str) -> str:
        """Return one field of one secret."""
        if not secret_id.isdigit():
            raise SecretError(
                f"delinea addressing requires a numeric secret id, got {secret_id!r}"
            )
        if not slug.replace("-", "").replace("_", "").isalnum():
            raise SecretError(f"delinea field slug is not a plain identifier: {slug!r}")

        value = self._field_once(secret_id, slug, self._bearer())
        if value is not None:
            return value
        # One retry, after a forced refresh: a token can be revoked server-side
        # before it expires. A second 401 is a real authorisation problem and
        # retrying it would just lock the account out.
        value = self._field_once(secret_id, slug, self._authenticate(), final=True)
        assert value is not None  # _field_once raises on final=True
        return value

    def _field_once(
        self, secret_id: str, slug: str, token: str, final: bool = False
    ) -> str | None:
        import httpx

        try:
            response = self._client.get(
                f"/api/v1/secrets/{secret_id}/fields/{slug}",
                params={"noAutoCheckout": "true", "autoComment": self._run_id or "secops-ingest"},
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise SecretError(f"secret server unreachable reading secret {secret_id}") from exc
        if response.status_code == 401 and not final:
            return None
        if response.status_code == 404:
            raise SecretNotFound(f"{secret_id}.{slug}")
        if response.status_code >= 400:
            raise SecretError(
                f"secret server returned {response.status_code} reading secret {secret_id}"
            )
        body = response.json()
        # The single-field endpoint returns the bare value for simple fields and
        # {"itemValue": ...} for others.
        if isinstance(body, dict):
            if "itemValue" not in body:
                raise SecretError(f"secret {secret_id} field {slug} has no itemValue")
            return str(body["itemValue"])
        return str(body)

    def close(self) -> None:
        self._client.close()
