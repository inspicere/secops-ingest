"""HashiCorp Vault provider (optional extra).

Install with:  pip install secops-ingest[vault]
"""

from __future__ import annotations

import os
from typing import Any

from .base import SecretError, SecretNotFound, SecretProvider


class VaultSecretProvider(SecretProvider):
    """Resolve secrets from a HashiCorp Vault KV v2 mount."""

    def __init__(
        self,
        url: str | None = None,
        mount: str = "secret",
        path_prefix: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._url = url or os.environ.get("VAULT_ADDR")
        self._mount = mount or os.environ.get("SECOPS_VAULT_MOUNT", "secret")
        self._prefix = path_prefix or os.environ.get("SECOPS_VAULT_PREFIX", "")
        if not self._url:
            raise SecretError("Vault provider requires VAULT_ADDR")
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import hvac
            except ImportError as exc:  # pragma: no cover - depends on extra
                raise SecretError(
                    "Vault provider requires the 'vault' extra: "
                    "pip install secops-ingest[vault]"
                ) from exc
            # Token comes from VAULT_TOKEN or the agent; never from our config.
            self._client = hvac.Client(url=self._url)
        return self._client

    def _fetch(self, name: str) -> str:  # pragma: no cover - needs a live server
        client = self._get_client()
        path = f"{self._prefix}{name}" if self._prefix else name
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount, raise_on_deleted_version=True
            )
            data = resp["data"]["data"]
        except Exception as exc:
            raise SecretNotFound(name) from exc
        # Single-key secrets resolve directly; otherwise require a 'value' key
        # so behaviour is predictable across backends.
        if "value" in data:
            return str(data["value"])
        if len(data) == 1:
            return str(next(iter(data.values())))
        raise SecretError(f"secret has multiple keys and no 'value': {name}")
