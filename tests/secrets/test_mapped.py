from __future__ import annotations

import json

import pytest

from secops_ingest.secrets import Secret, SecretNotFound
from secops_ingest.secrets.base import SecretProvider
from secops_ingest.secrets.mapped import MappedSecretProvider
from secops_ingest.secrets.mapping import Posture

MAP = {
    "posture": "assured",
    "providers": {
        "root": {"kind": "vault_agent", "config": {"tag": "R"}},
        "child": {"kind": "delinea", "config": {"tag": "C"}, "credential": "child.bootstrap"},
    },
    "entries": {
        "child.bootstrap": {"provider": "root", "path": "boot", "field": "f"},
        "alpha.key": {"provider": "root", "path": "a", "field": "k"},
        "beta.token": {"provider": "child", "secret": "7", "field": "password"},
    },
}


class MapHolder(SecretProvider):
    """Stands in for the root provider that serves the map itself."""

    def __init__(self, doc: dict[str, object]) -> None:
        super().__init__()
        self._doc = doc
        self.requested: list[str] = []

    def _fetch(self, name: str) -> str:
        self.requested.append(name)
        if name == "secret-map":
            return json.dumps(self._doc)
        raise SecretNotFound(name)


class Recorder(SecretProvider):
    def __init__(self, tag: str, credential: Secret | None) -> None:
        super().__init__()
        self.tag = tag
        self.credential = credential
        self.calls: list[dict[str, str]] = []

    def fetch_locator(self, locator: dict[str, str]) -> str:
        self.calls.append(locator)
        return f"{self.tag}:{locator.get('field', '?')}"

    def _fetch(self, name: str) -> str:  # pragma: no cover - locator path is used
        raise AssertionError("MappedSecretProvider must use fetch_locator")


@pytest.fixture
def built():
    made: dict[str, Recorder] = {}

    def factory(kind: str, config: dict[str, str], credential: Secret | None) -> SecretProvider:
        rec = Recorder(config["tag"], credential)
        made[kind] = rec
        return rec

    holder = MapHolder(MAP)
    provider = MappedSecretProvider(map_source=holder, factory=factory)
    return provider, holder, made


def test_resolves_through_the_owning_provider(built):
    provider, _holder, made = built
    assert provider.get("alpha.key") == "R:k"
    assert made["vault_agent"].calls == [{"path": "a", "field": "k"}]


def test_a_brokered_provider_receives_its_credential_as_a_secret(built):
    provider, _holder, made = built
    assert provider.get("beta.token") == "C:password"
    cred = made["delinea"].credential
    assert isinstance(cred, Secret)
    assert cred.reveal() == "R:f"


def test_the_map_is_fetched_once(built):
    provider, holder, _made = built
    provider.get("alpha.key")
    provider.get("beta.token")
    assert holder.requested.count("secret-map") == 1


def test_an_unmapped_name_raises_secret_not_found(built):
    provider, _holder, _made = built
    with pytest.raises(SecretNotFound):
        provider.get("nothing.here")


def test_posture_and_kinds_are_exposed_for_the_run_ledger(built):
    provider, _holder, _made = built
    assert provider.posture is Posture.ASSURED
    assert provider.provider_kinds() == {"root": "vault_agent", "child": "delinea"}


def test_a_provider_is_built_once_and_reused(built):
    provider, _holder, made = built
    provider.get("beta.token")
    first = made["delinea"]
    provider.get("beta.token")
    provider.clear_cache()
    provider.get("beta.token")
    assert made["delinea"] is first


def test_a_malformed_map_fails_on_first_use_not_on_construction():
    holder = MapHolder({"posture": "assured", "providers": {}, "entries": {"a.b": {}}})
    provider = MappedSecretProvider(map_source=holder)
    with pytest.raises(Exception, match="unknown provider"):
        provider.get("a.b")


def test_a_provider_without_fetch_locator_falls_back_to_name_lookup():
    # The file and env providers take a name, not a locator. Under the dev
    # posture they must still work through the map.
    class ByName(SecretProvider):
        def _fetch(self, name: str) -> str:
            return f"name:{name}"

    doc = {
        "posture": "dev",
        "providers": {"f": {"kind": "byname", "config": {}}},
        "entries": {"a.b": {"provider": "f", "name": "a.b"}},
    }
    provider = MappedSecretProvider(
        map_source=MapHolder(doc),
        factory=lambda kind, config, credential: ByName(),
    )
    assert provider.get("a.b") == "name:a.b"


# -- only the needed chain is built ---------------------------------------------

CHAIN_MAP = {
    "posture": "assured",
    "providers": {
        "agent": {"kind": "vault_agent", "config": {"tag": "A"}},
        "pam": {"kind": "delinea", "config": {"tag": "P"}, "credential": "pam.cred"},
        "vault2": {"kind": "vault", "config": {"tag": "V"}, "credential": "vault2.cred"},
    },
    "entries": {
        "pam.cred": {"provider": "agent", "path": "pam", "field": "f"},
        "vault2.cred": {"provider": "agent", "path": "v2", "field": "f"},
        "xdr.key": {"provider": "vault2", "path": "xdr", "field": "k"},
        "phish.token": {"provider": "pam", "secret": "7", "field": "password"},
    },
}


def test_a_broken_pam_does_not_fail_names_that_never_use_it():
    # The global resolution order is agent, pam, vault2. Walking it built pam
    # on the way to vault2, so pam's broken credential failed xdr.key, which
    # never touches pam.
    built: list[str] = []

    def factory(kind: str, config: dict[str, str], credential: Secret | None) -> SecretProvider:
        if kind == "delinea":
            raise SecretNotFound("pam.cred")
        built.append(kind)
        return Recorder(config["tag"], credential)

    provider = MappedSecretProvider(map_source=MapHolder(CHAIN_MAP), factory=factory)
    assert provider.get("xdr.key") == "V:k"
    assert built == ["vault_agent", "vault"]
    with pytest.raises(SecretNotFound):
        provider.get("phish.token")


def test_a_provider_that_failed_to_build_is_retried():
    attempts = {"delinea": 0}

    def factory(kind: str, config: dict[str, str], credential: Secret | None) -> SecretProvider:
        if kind == "delinea":
            attempts["delinea"] += 1
            if attempts["delinea"] == 1:
                raise SecretNotFound("transient")
        return Recorder(config["tag"], credential)

    provider = MappedSecretProvider(map_source=MapHolder(CHAIN_MAP), factory=factory)
    with pytest.raises(SecretNotFound):
        provider.get("phish.token")
    assert provider.get("phish.token") == "P:password"


def test_a_map_naming_the_composite_as_a_kind_is_refused():
    from secops_ingest.secrets.mapping import InvalidMap

    doc = {
        "posture": "dev",
        "providers": {"inner": {"kind": "mapped"}},
        "entries": {"a.b": {"provider": "inner", "name": "a.b"}},
    }
    provider = MappedSecretProvider(map_source=MapHolder(doc))
    with pytest.raises(InvalidMap, match="kind 'mapped'"):
        provider.get("a.b")
