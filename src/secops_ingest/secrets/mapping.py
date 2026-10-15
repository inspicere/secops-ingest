"""The mapping document: which provider owns each logical name.

VALIDATED AT LOAD, NOT AT RESOLUTION. A map that names a provider nobody
registered, or whose providers form a credential cycle, is a configuration
error. Discovering it when a name is first resolved means discovering it inside
a scheduled run at 03:00, reported as an authentication failure. Every check
here runs before any work starts.

POSTURE IS PART OF THE DOCUMENT, not an environment variable, because it must
travel with the mapping it describes. A map that lists a file provider is not
an assured map, and saying so in the same document removes the possibility of
the two disagreeing.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .base import InvalidSecretName, SecretError, validate_name

#: Provider kinds that read from a local filesystem or process environment.
#: Permitted only under the dev posture. Keeping this list explicit -- rather
#: than inferring from a provider capability flag -- means a third-party
#: provider cannot opt itself into an assured deployment.
_LOCAL_KINDS = frozenset({"file", "env"})


class InvalidMap(SecretError):
    """The mapping document is not usable."""


class Posture(enum.StrEnum):
    """How much the deployment is allowed to trust its own filesystem."""

    ASSURED = "assured"
    DEV = "dev"


@dataclass(frozen=True)
class Entry:
    """One logical name and where to find it."""

    provider: str
    locator: dict[str, str]


@dataclass(frozen=True)
class ProviderSpec:
    """One provider instance: its kind, its config, and how it authenticates.

    `credential` is None for a ROOTED provider, which bootstraps itself (a
    credential-free Vault Agent socket, or a TPM-sealed systemd credential).
    Otherwise it is a logical name some other provider resolves, making this
    provider BROKERED.
    """

    kind: str
    config: dict[str, str] = field(default_factory=dict)
    credential: str | None = None


@dataclass(frozen=True)
class SecretMap:
    posture: Posture
    providers: dict[str, ProviderSpec]
    entries: dict[str, Entry]

    def roots(self) -> set[str]:
        """Providers that need no credential from another provider."""
        return {name for name, spec in self.providers.items() if spec.credential is None}

    def resolution_order(self) -> list[str]:
        """Providers in an order where each one's credential is resolvable.

        Roots first, then providers whose credential lives in an
        already-ordered provider. load_map() has proved this terminates.
        """
        remaining = dict(self.providers)
        ordered: list[str] = []
        while remaining:
            ready = [
                name
                for name, spec in remaining.items()
                if spec.credential is None
                or self.entries[spec.credential].provider in ordered
            ]
            if not ready:  # pragma: no cover - load_map rejects cycles first
                raise InvalidMap(f"cycle among providers: {', '.join(sorted(remaining))}")
            for name in sorted(ready):
                ordered.append(name)
                del remaining[name]
        return ordered


def _require_mapping(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvalidMap(f"{what} must be a mapping, got {type(value).__name__}")
    return value


def load_map(doc: object) -> SecretMap:
    """Parse and validate a mapping document.

    Raises:
        InvalidMap: for any structural problem, naming a specific cause.
    """
    body = _require_mapping(doc, "mapping document")

    if "posture" not in body:
        raise InvalidMap("posture is required; use 'assured' in production or 'dev' locally")
    raw_posture = body["posture"]
    try:
        posture = Posture(str(raw_posture))
    except ValueError as exc:
        allowed = ", ".join(p.value for p in Posture)
        raise InvalidMap(f"unknown posture {raw_posture!r}; expected one of {allowed}") from exc

    providers: dict[str, ProviderSpec] = {}
    for name, raw in _require_mapping(body.get("providers", {}), "providers").items():
        spec_body = _require_mapping(raw, f"provider {name!r}")
        kind = spec_body.get("kind")
        if not isinstance(kind, str) or not kind:
            raise InvalidMap(f"provider {name!r} needs a 'kind'")
        if posture is Posture.ASSURED and kind in _LOCAL_KINDS:
            raise InvalidMap(
                f"posture 'assured' forbids provider kind {kind!r}: it reads from "
                "the local filesystem or environment. Use 'dev' only outside production."
            )
        credential = spec_body.get("credential")
        if credential is not None and not isinstance(credential, str):
            raise InvalidMap(f"provider {name!r} credential must be a string")
        config = _require_mapping(spec_body.get("config", {}), f"provider {name!r} config")
        providers[name] = ProviderSpec(
            kind=kind,
            config={str(k): str(v) for k, v in config.items()},
            credential=credential,
        )

    entries: dict[str, Entry] = {}
    for name, raw in _require_mapping(body.get("entries", {}), "entries").items():
        entry_body = _require_mapping(raw, f"entry {name!r}")
        try:
            validate_name(name)
        except InvalidSecretName as exc:
            raise InvalidMap(f"invalid secret name {name!r}") from exc
        provider = entry_body.get("provider")
        if not isinstance(provider, str) or provider not in providers:
            raise InvalidMap(
                f"entry {name!r} names unknown provider {provider!r}; "
                f"known: {', '.join(sorted(providers)) or '(none)'}"
            )
        entries[name] = Entry(
            provider=provider,
            locator={str(k): str(v) for k, v in entry_body.items() if k != "provider"},
        )

    for name, spec in providers.items():
        if spec.credential is not None and spec.credential not in entries:
            raise InvalidMap(
                f"provider {name!r} credential {spec.credential!r} is not an entry in this map"
            )

    if providers and not any(spec.credential is None for spec in providers.values()):
        # With no root, every provider points at another, so the graph must cycle.
        raise InvalidMap(
            "no root provider: every provider depends on another for its credential, "
            f"forming a cycle: {', '.join(sorted(providers))}"
        )

    _reject_cycles(providers, entries)
    return SecretMap(posture=posture, providers=providers, entries=entries)


def _reject_cycles(providers: dict[str, ProviderSpec], entries: dict[str, Entry]) -> None:
    """Refuse a map where providers depend on each other for credentials."""
    pending = {
        name: entries[spec.credential].provider
        for name, spec in providers.items()
        if spec.credential is not None
    }
    settled = {name for name, spec in providers.items() if spec.credential is None}
    while pending:
        ready = [name for name, dep in pending.items() if dep in settled]
        if not ready:
            raise InvalidMap(
                f"cycle among providers: {', '.join(sorted(pending))}. "
                "Each depends on another for its own credential."
            )
        for name in ready:
            settled.add(name)
            del pending[name]
