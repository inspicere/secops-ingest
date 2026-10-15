"""Resolve each name through the provider that owns it.

This is itself a SecretProvider, so every existing caller keeps working: the
contract is still one method taking a logical name. What changes is that the
backend is no longer a single global choice -- a deployment can read Cortex
credentials from Vault and a phishing token from Delinea in the same run.

THE MAP COMES FROM A PROVIDER, NOT A FILE. `map_source` is the root provider,
which bootstraps without a credential (a Vault Agent socket). Reading the map
from disk would reintroduce exactly the file this design exists to delete.

PROVIDERS ARE BUILT IN DEPENDENCY ORDER. A brokered provider's own credential
is a logical name, so it cannot be constructed until the provider holding that
name exists. SecretMap.resolution_order() gives the order, and load_map() has
already proved there are no cycles.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .base import SecretError, SecretNotFound, SecretProvider
from .mapping import Posture, SecretMap, load_map
from .secret import Secret

#: Signature of the thing that turns a map entry into a live provider.
ProviderFactory = Callable[[str, dict[str, str], Secret | None], SecretProvider]


class MappedSecretProvider(SecretProvider):
    """Dispatch each logical name to the provider the map assigns it."""

    def __init__(
        self,
        map_source: SecretProvider | None = None,
        map_name: str = "secret-map",
        factory: ProviderFactory | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        if map_source is None:
            raise SecretError("MappedSecretProvider requires a map_source provider")
        self._source = map_source
        self._map_name = map_name
        self._factory = factory or _default_factory
        self._map: SecretMap | None = None
        self._built: dict[str, SecretProvider] = {}

    # -- map loading --------------------------------------------------------

    def _load(self) -> SecretMap:
        """Fetch and validate the map once.

        Deliberately lazy. Constructing this provider must not require the
        backend to be reachable, so that a unit can be configured before Vault
        Agent is up and fail on first use with a clear error rather than on
        import.
        """
        if self._map is None:
            raw = self._source.get(self._map_name)
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SecretError(f"secret map {self._map_name!r} is not valid JSON") from exc
            # An injected factory owns its own vocabulary of kinds.
            self._map = load_map(doc, check_kinds=self._factory is _default_factory)
        return self._map

    @property
    def posture(self) -> Posture:
        """The posture the map declares. Recorded on every run row."""
        return self._load().posture

    def provider_kinds(self) -> dict[str, str]:
        """Provider name to kind, for the run ledger and the console."""
        return {name: spec.kind for name, spec in self._load().providers.items()}

    # -- provider construction ---------------------------------------------

    def _provider_for(self, name: str) -> SecretProvider:
        """Return the live provider called `name`, building it if needed."""
        if name in self._built:
            return self._built[name]
        mapping = self._load()
        for provider_name in mapping.resolution_order():
            if provider_name in self._built:
                continue
            spec = mapping.providers[provider_name]
            credential = (
                self.get_secret(spec.credential) if spec.credential is not None else None
            )
            self._built[provider_name] = self._factory(spec.kind, spec.config, credential)
            if provider_name == name:
                break
        return self._built[name]

    # -- resolution ---------------------------------------------------------

    def _fetch(self, name: str) -> str:
        mapping = self._load()
        entry = mapping.entries.get(name)
        if entry is None:
            raise SecretNotFound(name)
        provider = self._provider_for(entry.provider)
        locate: Any = getattr(provider, "fetch_locator", None)
        if callable(locate):
            return str(locate(entry.locator))
        # Providers that address by name rather than by locator -- file and
        # env, used under the dev posture -- take the entry's `name` field,
        # falling back to the logical name itself.
        return provider.get(entry.locator.get("name", name))

    def clear_cache(self) -> None:
        """Drop cached values but keep live providers.

        A rotation changes values, not topology. Rebuilding providers would
        re-authenticate every backend to re-read one secret.
        """
        super().clear_cache()


def _default_factory(
    kind: str, config: dict[str, str], credential: Secret | None
) -> SecretProvider:
    """Build a provider by kind, using the package's own registry."""
    from . import get_provider

    kwargs: dict[str, object] = dict(config)
    if credential is not None:
        kwargs["credential"] = credential
    return get_provider(kind, **kwargs)
