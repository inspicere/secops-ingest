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


def available_backends() -> list[str]:
    """Registered backend names (imported late: the package imports this module)."""
    from . import available_backends as _available

    return _available()

#: The only provider kinds an assured deployment accepts: Vault and
#: privileged-access managers. This is an ALLOWLIST, so any kind not named
#: here -- a third-party plugin that happens to read a file, or a misspelling --
#: is refused rather than waved through. Compared lowercased. Adding a PAM
#: backend means adding it here deliberately.
_PAM_KINDS = frozenset({"vault", "vault_agent", "delinea"})

_TOP_LEVEL_KEYS = frozenset({"posture", "providers", "entries"})
_PROVIDER_KEYS = frozenset({"kind", "config", "credential"})


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


def load_map(doc: object, *, check_kinds: bool = True) -> SecretMap:
    """Parse and validate a mapping document.

    Args:
        check_kinds: require every provider kind to be a registered backend.
            Disable only when the caller supplies its own provider factory and
            so owns the vocabulary of kinds.

    Raises:
        InvalidMap: for any structural problem, naming a specific cause.
    """
    body = _require_mapping(doc, "mapping document")

    unknown_top = sorted(set(body) - _TOP_LEVEL_KEYS)
    if unknown_top:
        raise InvalidMap(
            f"unknown top-level key(s) {', '.join(map(repr, unknown_top))}; "
            f"expected only {', '.join(sorted(_TOP_LEVEL_KEYS))}"
        )
    registered = frozenset(available_backends()) if check_kinds else frozenset()

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
        unknown_keys = sorted(set(spec_body) - _PROVIDER_KEYS)
        if unknown_keys:
            raise InvalidMap(
                f"provider {name!r} has unknown key(s) {', '.join(map(repr, unknown_keys))}; "
                f"expected only {', '.join(sorted(_PROVIDER_KEYS))}"
            )
        if posture is Posture.ASSURED and kind.lower() not in _PAM_KINDS:
            raise InvalidMap(
                f"posture 'assured' forbids provider kind {kind!r}: only "
                f"{', '.join(sorted(_PAM_KINDS))} are accepted. "
                "Use 'dev' only outside production."
            )
        if check_kinds and kind not in registered:
            raise InvalidMap(
                f"provider {name!r} has unregistered kind {kind!r}; "
                f"registered: {', '.join(sorted(registered))}"
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
