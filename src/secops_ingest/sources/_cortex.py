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
    200  standard  WITH x-xdr-auth-id      <- both tenants, at that time
    401  advanced  WITH x-xdr-auth-id      <- see the correction below

BOTH MODES ARE SUPPORTED, selected per vendor by SECOPS_<VENDOR>_AUTH_MODE.

The fourth line above was read as "these tenants issue Standard keys". That
inference does not follow: sending Advanced headers with a STANDARD key returns
401 too, so the experiment could not tell a tenant refusing Advanced from a key
that was simply not an Advanced one. It was also overtaken -- on 2026-10-08 the
XDR tenant returned 401 to Standard auth on all three of its connectors while
XSOAR kept working, because that key had become an Advanced key.

An Advanced key is never sent. Authorization carries

    sha256(api_key + nonce + timestamp)

with the nonce and the millisecond timestamp alongside it, and `x-xdr-auth-id`
is required in both modes -- which is the one thing the original measurement
established beyond doubt.

The id is not handed over when the key is copied; it is the ID column of the
console's API Keys table, which is why it can appear not to exist at all.

CREDENTIALS ARE ONE SECRET PER VENDOR, ADDRESSED <vendor>.<field>. A key and
its id are issued and rotated together, so they share a version history rather
than occupying separate paths where a half-applied rotation pairs a new key
with an old id.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
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
    # "standard" or "advanced". Carried on the credential rather than read from
    # the environment inside headers(), so the mode is resolved once, validated
    # once, and travels with the key it describes.
    auth_mode: str = "standard"


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

    # Keyed on the SECRET name, not the connector name, so the three XDR
    # connectors -- which all resolve the "xdr" secret -- inherit one setting.
    # A key is Standard or Advanced as a property of the key itself; having to
    # set it per connector would let them disagree about the same credential.
    var = f"SECOPS_{secret.upper().replace('-', '_').replace('.', '_')}_AUTH_MODE"
    mode = (os.environ.get(var) or "standard").strip()
    if mode not in ("standard", "advanced"):
        # Refused rather than defaulted. Falling back to Standard on a typo
        # 401s against an Advanced tenant and is indistinguishable from a bad
        # credential, which is a long way to travel for a misspelling.
        raise ValueError(
            f"{var} must be 'standard' or 'advanced', got {mode!r}")

    return CortexCreds(key=key, key_id=key_id,
                       base=f"{parts.scheme or 'https'}://{host}{path}",
                       auth_mode=mode)


def headers(creds: CortexCreds) -> dict[str, str]:
    """Build the auth headers for one request.

    CALL THIS PER REQUEST, not once per run. In Standard mode the result is
    constant and the call is free, but an Advanced signature carries a nonce and
    a timestamp: one nonce reused across a run is a replay, and one timestamp
    goes stale. A 90-day alerts backfill is thousands of requests over a long
    run, so "build it once in authenticate()" is correct for Standard and wrong
    for Advanced.
    """
    if creds.auth_mode == "advanced":
        # 64 characters, which is what the console's own examples use.
        nonce = secrets.token_hex(32)
        # MILLISECONDS. Seconds is ~1000x too small, reads as wildly stale, and
        # is rejected as a replay rather than as a bad key -- so the symptom
        # points at the credential instead of at the clock.
        timestamp = str(int(time.time() * 1000))
        signature = hashlib.sha256(
            f"{creds.key}{nonce}{timestamp}".encode()).hexdigest()
        return {
            # The key itself never goes on the wire in this mode.
            "Authorization": signature,
            "x-xdr-auth-id": creds.key_id,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Content-Type": "application/json",
        }

    return {
        "Authorization": creds.key,
        "x-xdr-auth-id": creds.key_id,
        "Content-Type": "application/json",
    }
