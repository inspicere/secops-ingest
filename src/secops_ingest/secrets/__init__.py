"""Pluggable secret resolution.

Backend is selected by ``SECOPS_SECRETS_BACKEND`` (default ``env``).

Third parties can add backends without forking by registering an entry point::

    [project.entry-points."secops_ingest.secret_providers"]
    my_backend = "my_pkg.provider:MyProvider"

An entry point cannot replace a backend that ships in core. See _BUILTIN.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from importlib.metadata import entry_points

from .base import (
    InvalidSecretName,
    SecretError,
    SecretNotFound,
    SecretProvider,
    validate_name,
)
from .bootstrap import mapped_from_environment
from .env import EnvSecretProvider
from .file import FileSecretProvider
from .mapped import MappedSecretProvider
from .secret import Secret

__all__ = [
    "EnvSecretProvider",
    "FileSecretProvider",
    "InvalidSecretName",
    "MappedSecretProvider",
    "Secret",
    "SecretError",
    "SecretNotFound",
    "SecretProvider",
    "get_provider",
    "validate_name",
]

ENTRY_POINT_GROUP = "secops_ingest.secret_providers"

#: Backends that ship in core. The PAM kinds are import strings, loaded only
#: when asked for, because each needs an optional extra (hvac or httpx) that a
#: default install does not have.
#:
#: They are registered here as well as by entry point because entry points
#: exist only once the package is installed. Running from src/ -- the test
#: suite, or a copied tree with no dist-info -- previously left vault,
#: vault_agent and delinea unregistered, so every assured map was refused as
#: naming an unknown kind and the whole secret layer went dark.
#:
#: Core names also win over entry points. The assured posture trusts a provider
#: because of its kind name (mapping._PAM_KINDS), so a third-party distribution
#: advertising "vault_agent" must not be able to stand in for the real one.
_BUILTIN: dict[str, Callable[..., SecretProvider] | str] = {
    "env": EnvSecretProvider,
    "file": FileSecretProvider,
    # Composite: dispatches per name via a map served by a root provider. The
    # constructor builds that root from SECOPS_SECRETS_MAP_SOURCE; see
    # bootstrap.py.
    "mapped": mapped_from_environment,
    "vault": "secops_ingest.secrets.vault:VaultSecretProvider",
    "vault_agent": "secops_ingest.secrets.vault_agent:VaultAgentSecretProvider",
    "delinea": "secops_ingest.secrets.delinea:DelineaSecretProvider",
}


def _load_builtin(backend: str) -> Callable[..., SecretProvider]:
    target = _BUILTIN[backend]
    if not isinstance(target, str):
        return target
    module, _, attr = target.partition(":")
    loaded: Callable[..., SecretProvider] = getattr(importlib.import_module(module), attr)
    return loaded


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

    if backend in _BUILTIN:
        return _load_builtin(backend)(**kwargs)

    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == backend:
            return ep.load()(**kwargs)  # type: ignore[no-any-return]

    raise SecretError(
        f"unknown secrets backend {backend!r}; available: {', '.join(available_backends())}"
    )
