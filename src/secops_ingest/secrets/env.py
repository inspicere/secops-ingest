"""Environment-variable secret provider.

Suitable for development, CI, and container platforms that inject secrets as
environment variables. Ships in core so the package installs and runs with no
proprietary dependency.
"""

from __future__ import annotations

import os

from .base import SecretNotFound, SecretProvider


class EnvSecretProvider(SecretProvider):
    """Read secrets from environment variables.

    ``phisher-api-token`` resolves to ``SECOPS_SECRET_PHISHER_API_TOKEN``.
    """

    def __init__(self, prefix: str = "SECOPS_SECRET_", **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._prefix = prefix

    def _env_key(self, name: str) -> str:
        return self._prefix + name.upper().replace("-", "_").replace(".", "_")

    def _fetch(self, name: str) -> str:
        try:
            return os.environ[self._env_key(name)]
        except KeyError as exc:
            # Report the logical name, not the env var, so the error does not
            # teach an attacker the naming scheme.
            raise SecretNotFound(name) from exc
