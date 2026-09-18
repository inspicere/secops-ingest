"""Shared configuration and authentication for the Cortex connectors.

Cortex XDR and Cortex XSOAR are separate products with separate tenants, but
they share one auth scheme and one credential shape, so this module exists to
keep that in a single place. Four connectors duplicating header construction
means fixing an auth bug four times.

STANDARD AUTH SENDS THE KEY *AND* THE KEY'S NUMERIC ID.

`x-xdr-auth-id` is not an Advanced-key header. The documentation's framing --
"Advanced adds a timestamp and a nonce" -- invites the conclusion that the id
belongs to Advanced as well. It does not. Measured against both production
tenants on 2026-09-14:

    401  standard  without x-xdr-auth-id
    401  advanced  without x-xdr-auth-id
    200  standard  WITH x-xdr-auth-id      <- both tenants
    401  advanced  WITH x-xdr-auth-id      <- these tenants issue Standard keys

The id is not handed over when the key is copied; it is the ID column of the
console's API Keys table, which is why it can appear not to exist at all.

CREDENTIALS ARE ONE SECRET PER VENDOR, ADDRESSED <vendor>.<field>. A key and
its id are issued and rotated together, so they share a version history rather
than occupying separate paths where a half-applied rotation pairs a new key
with an old id.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..redaction import register_secret
from ..secrets import get_provider


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 1:
        raise ValueError(f"{name} must be >= 1, got {value}")
    return value


@dataclass(frozen=True)
class CortexCreds:
    """Resolved credentials and the API base URL for one Cortex tenant."""

    key: str
    key_id: str
    base: str


def resolve(secret: str, path: str) -> CortexCreds:
    """Read one vendor secret and build its API base URL.

    The tenant FQDN is stored in Vault rather than in inventory: it is the
    identifier this platform keeps out of the repository, and a connector that
    reads it from configuration would put it in a file on every host.
    """
    provider = get_provider()
    key = provider.get(f"{secret}.api_key")
    key_id = provider.get(f"{secret}.api_key_id")
    url = provider.get(f"{secret}.url")

    # Registered so that a traceback or a debug-level httpx log cannot spill it.
    # The redaction filter is a backstop, not permission to log it.
    register_secret(key)

    parts = urlsplit(url if "://" in url else f"https://{url}")
    host = parts.netloc
    # The API host carries a literal `api-` prefix. Accept the stored value with
    # or without it so an operator pasting the console URL still works.
    if not host.startswith("api-"):
        host = f"api-{host}"

    # The tenant FQDN is registered for the same reason the key is, and it is
    # not belt-and-braces. httpx logs the full request URL at INFO, and cli.py
    # configures INFO by default with the RedactingFilter attached -- and that
    # filter only scrubs values someone registered. Without this line the
    # identifier this module deliberately keeps out of the repository is written
    # to the journal on every single request.
    #
    # It also neutralises CortexCreds' default __repr__, which prints `base`
    # verbatim into any traceback that happens to carry the dataclass.
    register_secret(host)

    return CortexCreds(key=key, key_id=key_id,
                       base=f"{parts.scheme or 'https'}://{host}{path}")


def headers(creds: CortexCreds) -> dict[str, str]:
    """Standard-key headers. Regenerating per request is unnecessary here.

    Unlike Advanced auth there is no nonce or timestamp, so these are constant
    for the life of a run and safe to build once.
    """
    return {
        "Authorization": creds.key,
        "x-xdr-auth-id": creds.key_id,
        "Content-Type": "application/json",
    }
