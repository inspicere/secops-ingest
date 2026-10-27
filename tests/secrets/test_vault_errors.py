"""VaultSecretProvider says what failed, and refuses cleartext to a remote Vault.

Every hvac failure used to become SecretNotFound, so an expired VAULT_TOKEN,
a sealed Vault or an unreachable server read in pipeline health as "secret
not found: xdr.api_key" and sent the operator looking for a missing KV entry.
Only a missing path is SecretNotFound now. Uses a stub client, never a server;
the error split needs hvac's own exception types, so it skips without them.
"""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.secrets import SecretError, SecretNotFound
from secops_ingest.secrets.vault import VaultSecretProvider


class RaisingKv:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def read_secret_version(self, **_: Any) -> dict[str, Any]:
        raise self.exc


def provider_raising(exc: Exception) -> VaultSecretProvider:
    p = VaultSecretProvider(url="http://127.0.0.1:1")  # never dialled
    kv = type("_K", (), {"v2": RaisingKv(exc)})()
    p._client = type("_C", (), {"secrets": type("_S", (), {"kv": kv})()})()
    return p


def _hvac() -> Any:
    return pytest.importorskip("hvac.exceptions", reason="needs the 'vault' extra")


def test_a_missing_path_is_not_found() -> None:
    with pytest.raises(SecretNotFound):
        provider_raising(_hvac().InvalidPath("gone")).get("xdr.api_key")


@pytest.mark.parametrize("name", ["Forbidden", "Unauthorized"])
def test_a_denied_token_is_an_error_not_a_missing_secret(name: str) -> None:
    exc = getattr(_hvac(), name)("permission denied")
    with pytest.raises(SecretError, match="denied access") as caught:
        provider_raising(exc).get("xdr.api_key")
    assert not isinstance(caught.value, SecretNotFound)
    assert "xdr.api_key" in str(caught.value)


def test_a_sealed_vault_says_so() -> None:
    with pytest.raises(SecretError, match="sealed") as caught:
        provider_raising(_hvac().VaultDown("sealed")).get("xdr.api_key")
    assert not isinstance(caught.value, SecretNotFound)


def test_an_unreachable_vault_says_so() -> None:
    _hvac()
    import requests

    with pytest.raises(SecretError, match="unreachable") as caught:
        provider_raising(requests.exceptions.ConnectionError("refused")).get("xdr.api_key")
    assert not isinstance(caught.value, SecretNotFound)


def test_a_tls_failure_says_so() -> None:
    _hvac()
    import requests

    with pytest.raises(SecretError, match="TLS"):
        provider_raising(requests.exceptions.SSLError("bad cert")).get("xdr.api_key")


def test_anything_else_names_the_failure_type_but_not_its_text() -> None:
    with pytest.raises(SecretError, match=r"\(RuntimeError\)") as caught:
        provider_raising(RuntimeError("secret/data/secops/xdr exploded")).get("xdr.api_key")
    assert not isinstance(caught.value, SecretNotFound)
    assert "secret/data" not in str(caught.value)


# -- scheme ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://vault.example.com:8200", "http://127.0.0.1:8200", "http://localhost:8200",
     "http://[::1]:8200"],
)
def test_https_or_loopback_is_accepted(url: str) -> None:
    VaultSecretProvider(url=url)


@pytest.mark.parametrize(
    "url", ["http://vault.example.com:8200", "http://10.0.0.5:8200", "ftp://127.0.0.1"]
)
def test_cleartext_to_a_remote_vault_is_refused(url: str) -> None:
    with pytest.raises(SecretError, match="must use https"):
        VaultSecretProvider(url=url)


def test_the_scheme_check_applies_to_vault_addr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "http://vault.example.com:8200")
    with pytest.raises(SecretError, match="must use https"):
        VaultSecretProvider()
