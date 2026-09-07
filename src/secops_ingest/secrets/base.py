"""Secret provider interface.

The contract is deliberately one method. Richer interfaces (versions, leases,
metadata) are supported unevenly across backends and become a compatibility
burden the moment a second backend exists.

Implementations MUST NOT:
  - write secret values to disk
  - log secret values
  - include secret values in exception messages or ``repr``
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

#: Secret names are logical identifiers, not paths. Restricting the character
#: set here is what makes path-based providers safe (see FileSecretProvider).
_VALID_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SecretError(Exception):
    """Base class for secret resolution failures."""


class SecretNotFound(SecretError):
    """A provider could not resolve a name.

    Carries the *name* only. Never the value, and never backend internals that
    would help an attacker map the secret store.
    """

    def __init__(self, name: str) -> None:
        super().__init__(f"secret not found: {name}")
        self.name = name


class InvalidSecretName(SecretError):
    """The requested name is not a valid secret identifier."""


def validate_name(name: str) -> str:
    """Return ``name`` if it is a valid secret identifier, else raise.

    Rejects path separators, traversal sequences, and anything outside a
    conservative character set. Every provider calls this before use, so a
    caller cannot reach outside the backend's namespace regardless of which
    backend is configured.
    """
    if not isinstance(name, str) or not _VALID_NAME.match(name):
        raise InvalidSecretName(f"invalid secret name: {name!r}")
    return name


class SecretProvider(ABC):
    """Resolve a logical secret name to its value."""

    #: Values are held in memory for the life of the provider. Callers fetch
    #: once per run; this avoids re-hitting the backend for repeated lookups
    #: without ever persisting anything.
    def __init__(self, *, cache: bool = True) -> None:
        self._cache: dict[str, str] | None = {} if cache else None

    def get(self, name: str) -> str:
        """Return the secret value for ``name``.

        Raises:
            InvalidSecretName: the name is not a valid identifier.
            SecretNotFound: the backend has no such secret.
            SecretError: the backend could not be reached.
        """
        validate_name(name)
        if self._cache is not None and name in self._cache:
            return self._cache[name]
        value = self._fetch(name)
        if self._cache is not None:
            self._cache[name] = value
        return value

    @abstractmethod
    def _fetch(self, name: str) -> str:
        """Backend-specific retrieval. ``name`` is already validated."""

    def clear_cache(self) -> None:
        """Drop cached values. Call after a rotation mid-process."""
        if self._cache is not None:
            self._cache.clear()

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Deliberately does not include configuration that could reveal store
        # layout, and never includes values.
        return f"<{type(self).__name__}>"
