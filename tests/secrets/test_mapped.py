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
        "root": {"kind": "fake_root", "config": {"tag": "R"}},
        "child": {"kind": "fake_child", "config": {"tag": "C"}, "credential": "child.bootstrap"},
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
    assert made["fake_root"].calls == [{"path": "a", "field": "k"}]


def test_a_brokered_provider_receives_its_credential_as_a_secret(built):
    provider, _holder, made = built
    assert provider.get("beta.token") == "C:password"
    cred = made["fake_child"].credential
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
    assert provider.provider_kinds() == {"root": "fake_root", "child": "fake_child"}


def test_a_provider_is_built_once_and_reused(built):
    provider, _holder, made = built
    provider.get("beta.token")
    first = made["fake_child"]
    provider.get("beta.token")
    provider.clear_cache()
    provider.get("beta.token")
    assert made["fake_child"] is first


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
