"""Environment-variable secret provider.

Suitable for development, CI, and container platforms that inject secrets as
environment variables. Ships in core so the package installs and runs with no
proprietary dependency.
"""

from __future__ import annotations

import os
from typing import ClassVar

from .base import SecretNotFound, SecretProvider
from .mapping import Posture


class EnvSecretProvider(SecretProvider):
    """Read secrets from environment variables.

    ``wazuh-indexer-password`` resolves to
    ``SECOPS_SECRET_WAZUH_INDEXER_PASSWORD``.
    """

    #: An environment variable is not a PAM. Declared so that a run resolving through this
    #: provider records 'dev' rather than NULL: NULL reads as "not declared",
    #: and this provider's posture is known.
    posture: ClassVar[Posture] = Posture.DEV

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
