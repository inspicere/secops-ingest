"""Delinea Secret Server provider.

Needs the 'http' extra. It deliberately does NOT depend on python-tss-sdk --
see delinea_client.py for why.

AUTHENTICATION IS BROKERED OR ROOTED, and this provider does not care which.
It receives its client secret already resolved, as a Secret, from whatever the
mapping document says holds it: a Vault entry where Vault is present, or a
TPM-sealed systemd credential read by a file provider where it is not. The
previous version of this file assumed the SDK would resolve a machine-bound
credential by itself, which python-tss-sdk does not implement (upstream issue
#70), and called SecretServer(base_url) with one argument where the
constructor requires an authorizer -- so it could not have worked.
"""

from __future__ import annotations

import os
from typing import Any

from .base import SecretError, SecretProvider
from .delinea_client import SecretServerClient
from .secret import Secret


class DelineaSecretProvider(SecretProvider):
    """Resolve secrets from Delinea Secret Server by numeric id and field."""

    def __init__(
        self,
        base_url: str | None = None,
        client_id: str | None = None,
        credential: Secret | None = None,
        run_id: str | None = None,
        transport: Any | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        base_url = base_url or os.environ.get("SECOPS_DELINEA_URL")
        client_id = client_id or os.environ.get("SECOPS_DELINEA_CLIENT_ID")
        if not base_url:
            raise SecretError("Delinea provider requires base_url (or SECOPS_DELINEA_URL)")
        if not client_id:
            raise SecretError(
                "Delinea provider requires client_id (or SECOPS_DELINEA_CLIENT_ID)"
            )
        if credential is None:
            raise SecretError(
                "Delinea provider requires a credential: name it in the mapping "
                "document so another provider resolves it"
            )
        self._client = SecretServerClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=credential,
            run_id=run_id or os.environ.get("SECOPS_RUN_ID", ""),
            transport=transport,
        )

    def fetch_locator(self, locator: dict[str, str]) -> str:
        """Resolve a map entry: `secret` (numeric id) and `field`."""
        secret_id = locator.get("secret")
        if not secret_id:
            raise SecretError("delinea entry requires a 'secret' (numeric id)")
        return self._client.field(secret_id, locator.get("field", "password"))

    def _fetch(self, name: str) -> str:
        raise SecretError(
            f"delinea addressing is by numeric id; map {name!r} with 'secret' and 'field'"
        )
