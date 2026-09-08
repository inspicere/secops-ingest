"""Integration tests for VaultSecretProvider against a real server.

Run against any server implementing the Vault HTTP API. CI runs them against
**OpenBao**, which is the MPL-2.0 fork of Vault's last open-source branch — so
the package's claim to work with an open-source secret backend is demonstrated
rather than asserted. The same tests run unchanged against HashiCorp Vault.

Skipped unless VAULT_ADDR is set, so `pytest` on a laptop with no server still
passes and the suite keeps its no-network guarantee by default.

    docker run -d -p 8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=root \
        quay.io/openbao/openbao:latest server -dev
    VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root pytest tests/secrets -v
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from secops_ingest.secrets import (
    InvalidSecretName,
    SecretError,
    SecretNotFound,
)
from secops_ingest.secrets.vault import VaultSecretProvider

hvac = pytest.importorskip("hvac", reason="needs the 'vault' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("VAULT_ADDR"),
    reason="VAULT_ADDR is unset; no Vault-API server to test against",
)

MOUNT = "secret"


@pytest.fixture(scope="module")
def client() -> Any:
    c = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ.get("VAULT_TOKEN"))
    if not c.is_authenticated():
        pytest.fail("could not authenticate; check VAULT_TOKEN")
    # Dev mode mounts secret/ as kv-v2 already. Creating it when absent lets the
    # same tests run against a server that was not started in dev mode.
    try:
        c.sys.enable_secrets_engine(backend_type="kv", path=MOUNT, options={"version": "2"})
    except Exception:  # noqa: BLE001,S110 - already mounted is the common case
        pass
    return c


@pytest.fixture
def seed(client: Any) -> Any:
    """Write a secret under a unique name and return that name."""
    written: list[str] = []

    def _seed(data: dict[str, str]) -> str:
        name = f"it-{uuid.uuid4().hex[:12]}"
        client.secrets.kv.v2.create_or_update_secret(
            path=name, secret=data, mount_point=MOUNT
        )
        written.append(name)
        return name

    yield _seed

    for name in written:
        try:
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=name, mount_point=MOUNT
            )
        except Exception:  # noqa: BLE001,S110 - cleanup must not mask a test failure
            pass


def test_server_identifies_itself(client: Any) -> None:
    """Record which implementation answered, so a green run names its subject."""
    status = client.sys.read_health_status(method="GET")
    version = status.get("version") if isinstance(status, dict) else None
    print(f"\nVault-API server version: {version}")
    assert version, "server did not report a version"


def test_value_key_resolves(seed: Any) -> None:
    name = seed({"value": "s3cr3t-from-the-backend"})
    assert VaultSecretProvider().get(name) == "s3cr3t-from-the-backend"


def test_single_key_resolves_without_a_value_key(seed: Any) -> None:
    """One-key secrets resolve directly; that is the documented convenience."""
    name = seed({"password": "only-key-wins"})
    assert VaultSecretProvider().get(name) == "only-key-wins"


def test_value_key_wins_over_others(seed: Any) -> None:
    name = seed({"value": "correct", "note": "ignored"})
    assert VaultSecretProvider().get(name) == "correct"


def test_ambiguous_secret_is_an_error_not_a_guess(seed: Any) -> None:
    """Several keys and no 'value' must fail loudly.

    Picking one arbitrarily would resolve differently between runs, which is
    worse than not resolving at all.
    """
    name = seed({"username": "a", "password": "b"})
    with pytest.raises(SecretError):
        VaultSecretProvider().get(name)


def test_missing_secret_raises_not_found() -> None:
    with pytest.raises(SecretNotFound):
        VaultSecretProvider().get(f"absent-{uuid.uuid4().hex[:12]}")


def test_not_found_does_not_leak_backend_detail() -> None:
    name = f"absent-{uuid.uuid4().hex[:12]}"
    with pytest.raises(SecretNotFound) as exc:
        VaultSecretProvider().get(name)
    text = str(exc.value)
    assert name in text
    # The hvac/server exception carries the mount path, the API version prefix
    # and the server URL. It stays chained for debugging but must not reach the
    # message a caller logs.
    #
    # Assert on path-shaped leakage, not on the bare word: "secret" occurs in
    # the message's own English ("secret not found: ..."), so checking for MOUNT
    # alone fails on a correct implementation.
    assert f"{MOUNT}/data" not in text
    assert "/v1/" not in text
    assert "http://" not in text and "https://" not in text


def test_invalid_name_is_rejected_before_the_backend_is_touched() -> None:
    """A traversal attempt must not become a request at all."""
    provider = VaultSecretProvider(url="http://127.0.0.1:1")  # refuses connections
    with pytest.raises(InvalidSecretName):
        provider.get("../../etc/passwd")


def test_prefix_scopes_lookups(client: Any, seed: Any) -> None:
    name = seed({"value": "scoped"})
    # The same leaf name under a prefix that does not exist must not resolve to
    # the unprefixed secret.
    with pytest.raises(SecretNotFound):
        VaultSecretProvider(path_prefix="nonexistent-prefix/").get(name)


def test_cache_avoids_a_second_backend_call(seed: Any) -> None:
    name = seed({"value": "cached"})
    provider = VaultSecretProvider()
    assert provider.get(name) == "cached"
    calls: list[str] = []
    original = provider._fetch

    def counting(n: str) -> str:
        calls.append(n)
        return original(n)

    provider._fetch = counting  # type: ignore[method-assign]
    assert provider.get(name) == "cached"
    assert calls == [], "a cached value still hit the backend"
