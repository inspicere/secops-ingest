"""Pluggable secret resolution.

Backend is selected by ``SECOPS_SECRETS_BACKEND`` (default ``env``).

Third parties can add backends without forking by registering an entry point::

    [project.entry-points."secops_ingest.secret_providers"]
    my_backend = "my_pkg.provider:MyProvider"
"""

from __future__ import annotations

import os
from importlib.metadata import entry_points

from .base import (
    InvalidSecretName,
    SecretError,
    SecretNotFound,
    SecretProvider,
    validate_name,
)
from .env import EnvSecretProvider
from .file import FileSecretProvider

__all__ = [
    "EnvSecretProvider",
    "FileSecretProvider",
    "InvalidSecretName",
    "SecretError",
    "SecretNotFound",
    "SecretProvider",
    "get_provider",
    "validate_name",
]

ENTRY_POINT_GROUP = "secops_ingest.secret_providers"

#: Backends that ship in core and require no optional dependency.
_BUILTIN: dict[str, type[SecretProvider]] = {
    "env": EnvSecretProvider,
    "file": FileSecretProvider,
}


def available_backends() -> list[str]:
    """Return every backend name resolvable in this environment."""
    names = set(_BUILTIN)
    names.update(ep.name for ep in entry_points(group=ENTRY_POINT_GROUP))
    return sorted(names)


def get_provider(backend: str | None = None, **kwargs: object) -> SecretProvider:
    """Construct the configured secret provider.

    Args:
        backend: override ``SECOPS_SECRETS_BACKEND``.
        **kwargs: passed to the provider constructor.

    Raises:
        SecretError: the backend is unknown or its dependency is missing.
    """
    backend = backend or os.environ.get("SECOPS_SECRETS_BACKEND", "env")

    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == backend:
            return ep.load()(**kwargs)  # type: ignore[no-any-return]

    if backend in _BUILTIN:
        return _BUILTIN[backend](**kwargs)  # type: ignore[arg-type]

    raise SecretError(
        f"unknown secrets backend {backend!r}; available: {', '.join(available_backends())}"
    )
