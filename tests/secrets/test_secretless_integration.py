"""The whole chain against a real Vault-compatible server.

Mock transports prove we send the right request. They cannot prove the server
accepts it or that KV v2's nesting is what we assume. Both production bugs this
month were asserted correct by tests that compared strings, so this one talks
to a server.

What this file proves: a map round-trips through a real KV v2 mount, resolution
dispatches through that map to the secret it names, and the not-found paths
(unmapped name, absent field) behave against a real server.

What it does NOT prove: leases. lease() is not exercised here. Issuing and
revoking a credential needs Vault's database secrets engine backed by a
PostgreSQL service, and the openbao CI job has neither. That belongs in a job
that has both.

Skipped unless VAULT_ADDR and VAULT_TOKEN are set, matching
tests/secrets/test_vault_backend_integration.py.
"""

from __future__ import annotations

import json
import os

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

pytestmark = pytest.mark.skipif(
    not (os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN")),
    reason="VAULT_ADDR/VAULT_TOKEN unset; no server to test against",
)

from secops_ingest.secrets.mapped import MappedSecretProvider  # noqa: E402
from secops_ingest.secrets.mapping import Posture  # noqa: E402
from secops_ingest.secrets.vault_agent import VaultAgentSecretProvider  # noqa: E402

ADDR = os.environ.get("VAULT_ADDR", "")
TOKEN = os.environ.get("VAULT_TOKEN", "")


@pytest.fixture
def seeded():
    """Write a map and the secret it points at, then yield a provider.

    A TCP transport stands in for the Unix socket: OpenBao in CI listens on a
    port, and the socket path is a deployment detail the agent owns. What this
    exercises is the request shape and the response parsing.
    """
    client = httpx.Client(base_url=ADDR, headers={"X-Vault-Token": TOKEN}, timeout=10.0)
    doc = {
        "posture": "assured",
        "providers": {"vault": {"kind": "vault_agent", "config": {}}},
        "entries": {
            "alpha.key": {"provider": "vault", "path": "things/alpha", "field": "key"}
        },
    }
    client.post(
        "/v1/secret/data/secret-map", json={"data": {"value": json.dumps(doc)}}
    )
    client.post(
        "/v1/secret/data/things/alpha", json={"data": {"key": "real-value-123"}}
    )

    root = VaultAgentSecretProvider(transport=httpx.HTTPTransport(), mount="secret")
    # The agent injects the token in production. Here there is no agent, so the
    # fixture supplies one -- the only place in this file that holds a token.
    # Replacing _client orphans the one the constructor built, so close both.
    constructed = root._client
    root._client = httpx.Client(
        base_url=ADDR, headers={"X-Vault-Token": TOKEN}, timeout=10.0
    )
    yield root
    root._client.close()
    constructed.close()
    client.close()


def test_the_map_round_trips_through_a_real_kv_v2_mount(seeded):
    provider = MappedSecretProvider(
        map_source=seeded,
        factory=lambda kind, config, credential: seeded,
    )
    assert provider.posture is Posture.ASSURED
    assert provider.get("alpha.key") == "real-value-123"


def test_an_unmapped_name_is_not_found_against_a_real_server(seeded):
    from secops_ingest.secrets import SecretNotFound

    provider = MappedSecretProvider(
        map_source=seeded, factory=lambda kind, config, credential: seeded
    )
    with pytest.raises(SecretNotFound):
        provider.get("not.mapped")


def test_a_missing_field_on_a_real_secret_is_not_found(seeded):
    from secops_ingest.secrets import SecretNotFound

    with pytest.raises(SecretNotFound):
        seeded.fetch_locator({"path": "things/alpha", "field": "absent"})
