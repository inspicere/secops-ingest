"""Offline tests for VaultSecretProvider's <secret>.<field> addressing.

No server and no hvac. The provider builds its client lazily, so injecting a
stub covers the part that actually varies -- how a name is split and which
field is returned -- without the 'vault' extra installed. The integration
suite in test_vault_backend_integration.py proves the same behaviour against a
real server; this proves it on a laptop.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.secrets import SecretError, SecretNotFound
from secops_ingest.secrets.vault import VaultSecretProvider


class StubKvV2:
    """Stands in for hvac's kv.v2 API and records the path it was asked for."""

    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self.store = store
        self.paths: list[str] = []

    def read_secret_version(
        self, path: str, mount_point: str, raise_on_deleted_version: bool
    ) -> dict[str, Any]:
        self.paths.append(path)
        if path not in self.store:
            raise KeyError(path)          # hvac raises; the provider catches broadly
        return {"data": {"data": dict(self.store[path])}}


class StubClient:
    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self.secrets = type("_S", (), {"kv": type("_K", (), {"v2": StubKvV2(store)})()})()


def provider_for(
    store: dict[str, dict[str, str]], *, prefix: str = ""
) -> tuple[VaultSecretProvider, StubKvV2]:
    p = VaultSecretProvider(url="http://127.0.0.1:1", path_prefix=prefix)  # never dialled
    client = StubClient(store)
    # Injecting the lazily-built client; the provider never dials out.
    p._client = client
    return p, client.secrets.kv.v2


VENDOR = {"secops/xdr": {"url": "https://api.example.com", "api_key": "k", "api_key_id": "42"}}


def test_each_field_of_a_grouped_secret_resolves() -> None:
    p, _ = provider_for(VENDOR, prefix="secops/")
    assert p.get("xdr.url") == "https://api.example.com"
    assert p.get("xdr.api_key") == "k"
    assert p.get("xdr.api_key_id") == "42"


def test_the_prefix_applies_to_the_path_not_the_field() -> None:
    """Regression guard: prefixing the whole name would look for secops/xdr.url."""
    p, kv = provider_for(VENDOR, prefix="secops/")
    p.get("xdr.api_key")
    assert kv.paths == ["secops/xdr"]


def test_field_selection_resolves_what_is_ambiguous_unqualified() -> None:
    store = {"pair": {"username": "a", "password": "b"}}
    p, _ = provider_for(store)
    with pytest.raises(SecretError):
        p.get("pair")
    p2, _ = provider_for(store)
    assert p2.get("pair.password") == "b"


def test_a_typod_field_fails_rather_than_falling_back() -> None:
    """Falling back to the single key is how a connector authenticates with a URL."""
    p, _ = provider_for({"one": {"api_key": "k"}})
    with pytest.raises(SecretNotFound):
        p.get("one.api_kye")


def test_missing_field_error_names_the_logical_name_only() -> None:
    p, _ = provider_for({"one": {"api_key": "k"}})
    with pytest.raises(SecretNotFound) as exc:
        p.get("one.absent")
    text = str(exc.value)
    assert "one.absent" in text
    assert "secret/data" not in text and "/v1/" not in text


def test_unqualified_names_are_unchanged() -> None:
    p, _ = provider_for({"plain": {"value": "still-works"}})
    assert p.get("plain") == "still-works"


def test_unqualified_single_key_secret_is_unchanged() -> None:
    p, _ = provider_for({"plain": {"password": "only-key"}})
    assert p.get("plain") == "only-key"


def test_field_may_contain_dots_because_the_split_is_on_the_first() -> None:
    p, kv = provider_for({"s": {"a.b": "nested"}})
    assert p.get("s.a.b") == "nested"
    assert kv.paths == ["s"]


def test_a_dotted_name_for_an_absent_secret_is_not_found() -> None:
    p, _ = provider_for({})
    with pytest.raises(SecretNotFound):
        p.get("nosuch.field")
