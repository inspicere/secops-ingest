# tests/secrets/test_sealed_posture.py
"""Posture 'sealed': Delinea Secret Server as the root, with no Vault in front.

The shape a host with only Secret Server runs: systemd decrypts the map and the
SDK client's secret into CREDENTIALS_DIRECTORY, a file root reads the map from
there, and every secret a source uses is read from Secret Server at run time.
"""
from __future__ import annotations

import copy
import json

import pytest

from secops_ingest.secrets.mapping import InvalidMap, Posture, load_map

SEALED = {
    "posture": "sealed",
    "providers": {
        "creds": {"kind": "file"},
        "ss": {
            "kind": "delinea",
            "config": {"base_url": "https://pam.example.com/SecretServer",
                       "client_id": "sdk-client-1"},
            "credential": "ss_client_secret",
        },
    },
    "entries": {
        "ss_client_secret": {"provider": "creds", "name": "ss_client_secret"},
        "xdr_ro": {"provider": "ss", "secret": "101", "field": "api-key"},
        "warehouse_ingest_password": {"provider": "ss", "secret": "103", "field": "password"},
    },
}


def _with(**changes):
    doc = copy.deepcopy(SEALED)
    for path, value in changes.items():
        node = doc
        *parents, leaf = path.split("__")
        for p in parents:
            node = node[p]
        if value is None:
            del node[leaf]
        else:
            node[leaf] = value
    return doc


def test_a_pam_with_its_bootstrap_in_a_file_loads_as_sealed():
    assert load_map(SEALED).posture is Posture.SEALED


@pytest.mark.parametrize(
    "doc, message",
    [
        # A data secret from a file is a secret on the host.
        (_with(entries__xdr_ro={"provider": "creds", "name": "xdr_ro"}),
         "no PAM provider's credential"),
        (_with(providers__creds={"kind": "env"}), "forbids provider kind 'env'"),
        (_with(providers__creds={"kind": "file", "config": {"directory": "/etc/secops"}}),
         "may not name a directory"),
        # Without a PAM there is nothing for the bootstrap to unlock.
        ({"posture": "sealed", "providers": {"creds": {"kind": "file"}},
          "entries": {"a": {"provider": "creds"}}}, "at least one PAM"),
    ],
)
def test_sealed_refuses_anything_secret_on_the_host(doc, message):
    with pytest.raises(InvalidMap, match=message):
        load_map(doc)


def test_dev_accepts_what_sealed_refuses():
    doc = _with(entries__xdr_ro={"provider": "creds", "name": "xdr_ro"})
    doc["posture"] = "dev"
    assert load_map(doc).posture is Posture.DEV


# -- the root ----------------------------------------------------------------

class StaticRoot:
    def __init__(self, doc):
        self.doc = doc

    def get(self, name):
        return json.dumps(self.doc)


def _mapped(root_kind):
    from secops_ingest.secrets.mapped import MappedSecretProvider

    return MappedSecretProvider(map_source=StaticRoot(SEALED), root_kind=root_kind)


def test_sealed_needs_systemds_credentials_directory(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(InvalidMap, match="CREDENTIALS_DIRECTORY"):
        _ = _mapped("file").posture


@pytest.mark.parametrize("kind", ["env", "vault_agent"])
def test_sealed_is_served_only_by_a_file_root(monkeypatch, kind):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/x")
    with pytest.raises(InvalidMap, match="'file' root"):
        _ = _mapped(kind).posture


def test_a_file_root_under_systemd_serves_sealed(monkeypatch):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/x")
    assert _mapped("file").posture is Posture.SEALED


# -- end to end, through the real bootstrap ----------------------------------

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")


def test_a_run_resolves_through_secret_server_with_only_ciphertext_on_disk(
    monkeypatch, tmp_path
):
    """What a unit with LoadCredentialEncrypted= sees, end to end."""
    creds = tmp_path / "credentials"
    creds.mkdir()
    (creds / "secret-map").write_text(json.dumps(SEALED))
    (creds / "ss_client_secret").write_text("sdk-secret-value")
    for path in creds.iterdir():
        path.chmod(0o400)

    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path.endswith("/oauth2/token"):
            body = request.content.decode()
            assert "client_id=sdk-client-1" in body
            assert "client_secret=sdk-secret-value" in body
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 1200})
        assert request.url.path == "/SecretServer/api/v1/secrets/101/fields/api-key"
        return httpx.Response(200, json="xdr-key-value")

    real_client = httpx.Client

    class MockedClient(real_client):
        def __init__(self, *args, transport=None, **kwargs):
            super().__init__(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", MockedClient)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.delenv("SECOPS_SECRETS_DIR", raising=False)
    monkeypatch.setenv("SECOPS_SECRETS_BACKEND", "mapped")
    monkeypatch.setenv("SECOPS_SECRETS_MAP_SOURCE", "file")

    from secops_ingest.secrets import get_provider

    provider = get_provider()
    assert provider.get("xdr_ro") == "xdr-key-value"
    assert provider.posture is Posture.SEALED
    assert seen == ["/SecretServer/oauth2/token",
                    "/SecretServer/api/v1/secrets/101/fields/api-key"]
