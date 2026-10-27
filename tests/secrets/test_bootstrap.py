"""SECOPS_SECRETS_BACKEND=mapped, constructed from the environment alone.

Before this, get_provider("mapped") raised "requires a map_source provider" on
every call, because nothing could express the root, so the assured posture
could not be switched on from any entry point. These tests use the env and
file roots, which need no extra and no server; the vault_agent root is
constructed the same way through get_provider(kind).
"""

from __future__ import annotations

import json

import pytest

from secops_ingest.secrets import EnvSecretProvider, SecretError, get_provider
from secops_ingest.secrets.bootstrap import (
    DEFAULT_MAP_NAME,
    map_name_from_environment,
    root_kind_from_environment,
)
from secops_ingest.secrets.mapped import MappedSecretProvider
from secops_ingest.secrets.mapping import InvalidMap, Posture

DEV_MAP = {
    "posture": "dev",
    "providers": {"local": {"kind": "env"}},
    "entries": {"wazuh_indexer_password": {"provider": "local", "name": "wazuh-pw"}},
}


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for var in (
        "SECOPS_SECRETS_BACKEND",
        "SECOPS_SECRETS_MAP_SOURCE",
        "SECOPS_SECRETS_MAP_NAME",
        "SECOPS_SECRET_SECRET_MAP",
        "CREDENTIALS_DIRECTORY",
        "SECOPS_SECRETS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


# -- root kind and map name ------------------------------------------------------


def test_an_unset_root_names_the_variable(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(SecretError, match="SECOPS_SECRETS_MAP_SOURCE"):
        root_kind_from_environment()


@pytest.mark.parametrize("kind", ["vault", "delinea", "mapped", "nonsense"])
def test_a_kind_that_cannot_serve_the_map_is_refused(
    clean_env: pytest.MonkeyPatch, kind: str
) -> None:
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", kind)
    with pytest.raises(SecretError, match=f"unknown SECOPS_SECRETS_MAP_SOURCE '{kind}'"):
        root_kind_from_environment()


def test_the_map_name_defaults(clean_env: pytest.MonkeyPatch) -> None:
    assert map_name_from_environment() == DEFAULT_MAP_NAME == "secret-map"


def test_a_map_name_that_is_a_path_is_refused(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECOPS_SECRETS_MAP_NAME", "../secret-map")
    with pytest.raises(SecretError, match="SECOPS_SECRETS_MAP_NAME"):
        map_name_from_environment()


# -- get_provider("mapped") ------------------------------------------------------


def test_mapped_is_constructible_from_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", "env")
    clean_env.setenv("SECOPS_SECRET_SECRET_MAP", json.dumps(DEV_MAP))
    clean_env.setenv("SECOPS_SECRET_WAZUH_PW", "indexer-password-value")

    provider = get_provider("mapped")

    assert isinstance(provider, MappedSecretProvider)
    assert provider.posture is Posture.DEV
    assert provider.get("wazuh_indexer_password") == "indexer-password-value"


def test_the_cli_path_builds_it_from_the_backend_variable(
    clean_env: pytest.MonkeyPatch,
) -> None:
    # cli.py calls get_provider() with no argument when SECOPS_SECRETS_BACKEND
    # is set; that is the call that used to raise.
    clean_env.setenv("SECOPS_SECRETS_BACKEND", "mapped")
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", "env")
    clean_env.setenv("SECOPS_SECRET_SECRET_MAP", json.dumps(DEV_MAP))
    assert isinstance(get_provider(), MappedSecretProvider)


def test_a_file_root_serves_the_map_from_a_file(
    clean_env: pytest.MonkeyPatch, tmp_path
) -> None:
    (tmp_path / "secret-map").write_text(json.dumps(DEV_MAP))
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", "file")
    clean_env.setenv("SECOPS_SECRETS_DIR", str(tmp_path))

    assert get_provider("mapped").posture is Posture.DEV


def test_the_map_name_is_honoured(clean_env: pytest.MonkeyPatch, tmp_path) -> None:
    (tmp_path / "ingest-map").write_text(json.dumps(DEV_MAP))
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", "file")
    clean_env.setenv("SECOPS_SECRETS_MAP_NAME", "ingest-map")
    clean_env.setenv("SECOPS_SECRETS_DIR", str(tmp_path))

    assert get_provider("mapped").posture is Posture.DEV


@pytest.mark.parametrize("root", ["env", "file"])
def test_an_assured_map_from_a_local_root_is_refused(
    clean_env: pytest.MonkeyPatch, tmp_path, root: str
) -> None:
    # Never fail open: an assured map that anyone able to write a file can
    # rewrite is not assured, so it is refused rather than downgraded.
    assured = {
        "posture": "assured",
        "providers": {"v": {"kind": "vault_agent"}},
        "entries": {"x": {"provider": "v", "path": "x"}},
    }
    (tmp_path / "secret-map").write_text(json.dumps(assured))
    clean_env.setenv("SECOPS_SECRET_SECRET_MAP", json.dumps(assured))
    clean_env.setenv("SECOPS_SECRETS_DIR", str(tmp_path))
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", root)

    provider = get_provider("mapped")
    with pytest.raises(InvalidMap, match=f"cannot be served by a '{root}' root"):
        provider.get("x")


def test_mapped_without_a_root_says_which_variable_is_missing(
    clean_env: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SecretError, match="SECOPS_SECRETS_MAP_SOURCE"):
        get_provider("mapped")


def test_an_unbuildable_root_fails_construction(clean_env: pytest.MonkeyPatch) -> None:
    # A file root with no directory: the root's own error, at construction,
    # so the CLI fails the run before it starts rather than at first use.
    clean_env.setenv("SECOPS_SECRETS_MAP_SOURCE", "file")
    with pytest.raises(SecretError, match="requires a directory"):
        get_provider("mapped")


def test_an_explicit_map_source_bypasses_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    # The pre-existing constructor path: callers that build their own root.
    clean_env.setenv("SECOPS_SECRET_SECRET_MAP", json.dumps(DEV_MAP))
    provider = get_provider("mapped", map_source=EnvSecretProvider())
    assert provider.posture is Posture.DEV
