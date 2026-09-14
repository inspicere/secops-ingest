"""HashiCorp Vault provider (optional extra).

Install with:  pip install secops-ingest[vault]
"""

from __future__ import annotations

import os
from typing import Any

from .base import SecretError, SecretNotFound, SecretProvider


class VaultSecretProvider(SecretProvider):
    """Resolve secrets from a HashiCorp Vault KV v2 mount.

    A dot in the name selects a FIELD within a secret: ``xdr.api_key`` reads
    the ``api_key`` field of the secret at ``<prefix>xdr``. Without a dot the
    whole secret is resolved as before, via its ``value`` key or its only key.

    This exists because credentials that are issued and rotated together belong
    in one secret. An API key and its numeric key ID split across two KV paths
    are two writes, and a rotation that completes the first and fails the second
    leaves a key paired with the wrong ID -- which authenticates as nothing and
    gets diagnosed as "the new key doesn't work". Grouped, the pair has one
    version history and one check-and-set unit.

    The dot is a separator here, not a literal: a secret whose PATH contains a
    dot cannot be addressed by this provider. Paths are ours to choose and
    fields are what vary, so that trade is deliberate. The other backends
    already treat a dot as structure rather than as a character -- the env
    provider maps ``xdr.api_key`` to ``SECOPS_SECRET_XDR_API_KEY`` -- so this
    keeps one naming scheme across all three.
    """

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
        # Split on the FIRST dot: the field is everything after it, so a field
        # name may itself contain dots while the path stays a single segment.
        secret, _, field = name.partition(".")
        path = f"{self._prefix}{secret}" if self._prefix else secret
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount, raise_on_deleted_version=True
            )
            data = resp["data"]["data"]
        except Exception as exc:
            raise SecretNotFound(name) from exc
        if field:
            if field not in data:
                # The secret exists but has no such field. Reported as the
                # logical name, not as "field missing from path X", so the error
                # does not describe the store's layout to whatever logs it.
                raise SecretNotFound(name)
            return str(data[field])
        # Single-key secrets resolve directly; otherwise require a 'value' key
        # so behaviour is predictable across backends.
        if "value" in data:
            return str(data["value"])
        if len(data) == 1:
            return str(next(iter(data.values())))
        raise SecretError(f"secret has multiple keys and no 'value': {name}")
