"""The PAM backends are registered without package metadata.

Entry points exist only once the package is installed. Run from src/ -- the
test suite, or a copied tree with no dist-info -- vault, vault_agent and
delinea were unregistered, so load_map refused every assured map as naming an
unknown kind. These tests remove the entry points to prove the registry does
not depend on them.
"""

from __future__ import annotations

from importlib.metadata import EntryPoint

import pytest

import secops_ingest.secrets as secrets
from secops_ingest.secrets.mapping import load_map

ASSURED = {
    "posture": "assured",
    "providers": {"vault": {"kind": "vault_agent", "config": {"socket": "/run/agent.sock"}}},
    "entries": {"xdr.key": {"provider": "vault", "path": "secops/xdr", "field": "k"}},
}


@pytest.fixture
def no_entry_points(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "entry_points", lambda group: [])


def test_pam_kinds_are_available_without_an_install(no_entry_points: None) -> None:
    assert {"vault", "vault_agent", "delinea"} <= set(secrets.available_backends())


def test_an_assured_map_loads_without_an_install(no_entry_points: None) -> None:
    assert load_map(ASSURED).providers["vault"].kind == "vault_agent"


def test_a_builtin_pam_kind_resolves_to_the_core_class(no_entry_points: None) -> None:
    from secops_ingest.secrets.vault import VaultSecretProvider

    provider = secrets.get_provider("vault", url="https://vault.example.com")
    assert isinstance(provider, VaultSecretProvider)


def test_an_entry_point_cannot_shadow_a_core_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    # The assured allowlist trusts a provider by its kind name. A third-party
    # distribution advertising "vault" must not stand in for the real one.
    impostor = EntryPoint(
        name="vault", value="secops_ingest.secrets.env:EnvSecretProvider",
        group=secrets.ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(secrets, "entry_points", lambda group: [impostor])
    from secops_ingest.secrets.vault import VaultSecretProvider

    provider = secrets.get_provider("vault", url="https://vault.example.com")
    assert isinstance(provider, VaultSecretProvider)


def test_a_third_party_backend_with_a_new_name_still_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extra = EntryPoint(
        name="thirdparty", value="secops_ingest.secrets.env:EnvSecretProvider",
        group=secrets.ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(secrets, "entry_points", lambda group: [extra])
    assert isinstance(secrets.get_provider("thirdparty"), secrets.EnvSecretProvider)
    assert "thirdparty" in secrets.available_backends()
