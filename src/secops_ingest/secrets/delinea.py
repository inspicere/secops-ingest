"""Delinea Secret Server provider (optional extra).

Install with:  pip install secops-ingest[delinea]

Authentication is expected to come from an SDK client registration, so no
long-lived Secret Server credential lives on the worker host. The password
grant path is supported as a documented fallback for environments where SDK
client registration is unavailable.
"""

from __future__ import annotations

import os

from .base import SecretError, SecretNotFound, SecretProvider


class DelineaSecretProvider(SecretProvider):
    """Resolve secrets from Delinea Secret Server.

    Names map to secret *names* within a configured folder, so the folder
    grant is the security boundary: this provider can only reach what the SDK
    client is scoped to.
    """

    def __init__(
        self,
        base_url: str | None = None,
        folder: str | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._base_url = base_url or os.environ.get("SECOPS_DELINEA_URL")
        self._folder = folder or os.environ.get("SECOPS_DELINEA_FOLDER")
        if not self._base_url:
            raise SecretError("Delinea provider requires SECOPS_DELINEA_URL")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                # Imported lazily so the core package has no hard dependency
                # on a proprietary SDK.
                from delinea.secrets.server import SecretServer  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on extra
                raise SecretError(
                    "Delinea provider requires the 'delinea' extra: "
                    "pip install secops-ingest[delinea]"
                ) from exc
            self._client = self._build_client(SecretServer)
        return self._client

    def _build_client(self, secret_server_cls):  # pragma: no cover - needs a live server
        # SDK client registration is the intended path; the SDK resolves its
        # machine-bound credential itself.
        return secret_server_cls(self._base_url)

    def _fetch(self, name: str) -> str:  # pragma: no cover - needs a live server
        client = self._get_client()
        try:
            secret = client.get_secret_by_path(f"{self._folder}\\{name}")
            return secret.fields["password"].value
        except Exception as exc:
            # Never surface the backend's exception text: it can contain paths,
            # folder structure, or field contents.
            raise SecretNotFound(name) from exc
