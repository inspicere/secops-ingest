"""HashiCorp Vault provider (optional extra).

Install with:  pip install secops-ingest[vault]
"""

from __future__ import annotations

import importlib
import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

from .base import SecretError, SecretNotFound, SecretProvider


def _require_https(url: str) -> None:
    """Refuse a cleartext VAULT_ADDR unless it is this host.

    The token and every secret read travel over this connection. Loopback is
    allowed because a local Vault Agent listener on 127.0.0.1 is the usual way
    to reach Vault without a token in the unit, and that traffic never leaves
    the host. There is no override for anything else, for the same reason
    delinea_client has none: a flag that can be set by mistake defeats it.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() == "https":
        return
    host = (parts.hostname or "").lower()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if parts.scheme.lower() == "http" and loopback:
        return
    raise SecretError(
        "VAULT_ADDR must use https:// unless it is a loopback address "
        f"(the token is sent to it); got {url!r}"
    )


def _classify(name: str, exc: Exception) -> SecretError:
    """Turn an hvac or transport failure into an error that says what failed.

    Every failure used to read as "secret not found", so an expired token, a
    sealed Vault or an unreachable server sent the operator looking for a
    missing KV entry while every source was down. Only a missing path is
    SecretNotFound now. The messages carry the logical name and the kind of
    failure, never the path or the server's error text, which can describe the
    store's layout.
    """
    try:
        from hvac import exceptions as hv
    except ImportError:  # pragma: no cover - a live client implies hvac
        hv = None
    if hv is not None:
        if isinstance(exc, hv.InvalidPath):
            # Also what raise_on_deleted_version=True raises for a deleted version.
            return SecretNotFound(name)
        if isinstance(exc, (hv.Forbidden, hv.Unauthorized)):
            return SecretError(
                f"vault denied access reading {name} (token expired, revoked, or "
                "lacking a policy for this path?)"
            )
        if isinstance(exc, (hv.VaultDown, hv.VaultNotInitialized)):
            return SecretError(f"vault is sealed or not initialised; could not read {name}")
    try:
        # Imported by name: requests arrives with hvac, not with this package,
        # so a static import would fail type-checking in the default install.
        requests: Any = importlib.import_module("requests")
    except ImportError:  # pragma: no cover - hvac depends on requests
        requests = None
    if requests is not None:
        if isinstance(exc, requests.exceptions.SSLError):
            return SecretError(f"vault TLS verification failed reading {name}")
        if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            return SecretError(f"vault unreachable reading {name}")
    return SecretError(f"vault read failed for {name} ({type(exc).__name__})")


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
        _require_https(self._url)
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
            raise _classify(name, exc) from exc
        if not isinstance(data, dict):
            raise SecretError(f"vault response for {name} has no data block; is the mount KV v2?")
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
