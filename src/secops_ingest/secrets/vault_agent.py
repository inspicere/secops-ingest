"""Vault through a Vault Agent Unix socket, carrying no credential.

THE WORKER HOLDS NO TOKEN. Vault Agent is configured with
`use_auto_auth_token = true` on a `listener "unix"`, so it injects its own
token into every proxied request. This client therefore sends no
X-Vault-Token header at all -- not a sealed one, not a short-lived one, none.
Authorisation is membership of the group that owns the socket.

httpx RATHER THAN hvac, and that is forced rather than preferred. hvac is built
on requests, which cannot address a Unix socket without requests-unixsocket.
httpx supports it natively through HTTPTransport(uds=...). httpx is already a
dependency of the `http` extra.

This is a SEPARATE provider from VaultSecretProvider rather than a mode of it,
because the migration needs both alive at once: the AppRole path keeps working
while the agent is proved, and nothing switches until it is.
"""

from __future__ import annotations

from typing import Any

from .base import SecretError, SecretNotFound, SecretProvider

#: Any host works: the connection is a Unix socket, so the authority in the URL
#: is never resolved. A literal makes request logs readable.
_BASE = "http://vault-agent"
_TIMEOUT = 10.0


class VaultAgentSecretProvider(SecretProvider):
    """Read KV v2 secrets and leases through a local Vault Agent socket."""

    def __init__(
        self,
        socket: str | None = None,
        mount: str = "secret",
        prefix: str = "",
        transport: Any | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on extra
            raise SecretError(
                "the Vault Agent provider requires the 'http' extra: "
                "pip install secops-ingest[http]"
            ) from exc
        if transport is None:
            if not socket:
                raise SecretError("VaultAgentSecretProvider requires a socket path")
            transport = httpx.HTTPTransport(uds=socket)
        self._client = httpx.Client(transport=transport, base_url=_BASE, timeout=_TIMEOUT)
        self._mount = mount.strip("/")
        self._prefix = prefix

    # -- requests -----------------------------------------------------------

    def _get(self, url: str, *, kind: str) -> dict[str, Any]:
        """GET `url`, returning the `data` block.

        Error text names the kind of read and the HTTP status, and nothing
        else. It never carries the URL or path: a message with the path would
        map the secret store for anyone reading a log, and error_summary is
        written to the warehouse.
        """
        import httpx

        try:
            response = self._client.get(url)
        except httpx.HTTPError as exc:
            raise SecretError(f"vault agent unreachable while reading a {kind}") from exc
        if response.status_code == 404:
            raise SecretNotFound(f"vault {kind}")
        if response.status_code >= 400:
            raise SecretError(
                f"vault agent returned {response.status_code} while reading a {kind}"
            )
        body = response.json()
        data = body.get("data")
        if not isinstance(data, dict):
            raise SecretError(f"vault agent response for a {kind} has no data block")
        return data

    # -- KV v2 --------------------------------------------------------------

    def fetch_locator(self, locator: dict[str, str]) -> str:
        """Resolve a map entry: `path`, and optionally `field`."""
        path = locator.get("path")
        if not path:
            raise SecretError("vault entry requires a 'path'")
        full = f"{self._prefix}{path}".strip("/")
        data = self._get(f"/v1/{self._mount}/data/{full}", kind="secret")
        inner = data.get("data")
        if not isinstance(inner, dict):
            raise SecretError("vault secret has no nested data block; is the mount KV v2?")
        field = locator.get("field")
        if field:
            if field not in inner:
                raise SecretNotFound(f"vault secret field '{field}'")
            return str(inner[field])
        if "value" in inner:
            return str(inner["value"])
        if len(inner) == 1:
            return str(next(iter(inner.values())))
        raise SecretError(
            f"vault secret has {len(inner)} fields and no 'value'; name a field in the map"
        )

    def _fetch(self, name: str) -> str:
        """Resolve a bare name as a path under the prefix.

        Used for the mapping document itself, which the mapped provider asks
        for by name before any map exists to describe it.
        """
        return self.fetch_locator({"path": name})

    # -- leases -------------------------------------------------------------

    def lease(self, path: str) -> dict[str, str]:
        """Read a dynamic credential, e.g. `database/creds/ingest`.

        Returns the whole data block because a lease is a pair -- username and
        password are useless apart, and resolving them through two calls would
        risk two different leases.
        """
        clean = path.strip("/")
        data = self._get(f"/v1/{clean}", kind="lease")
        return {str(k): str(v) for k, v in data.items()}

    def close(self) -> None:
        self._client.close()
