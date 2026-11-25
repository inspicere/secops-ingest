"""Onboard this host as a Delinea Secret Server SDK client, once.

    python -m secops_ingest.secrets.onboard \\
        --url https://pam.example.com/SecretServer --rule secops-ingest \\
        --name worker-01 --client-id-file /etc/secops-ingest/ss-client-id \\
        < onboarding-key \\
      | systemd-creds encrypt --with-key=tpm2 --name=ss_client_secret - \\
            /etc/credstore.encrypted/ss_client_secret

An SDK client is how a host gets a credential of its own in Secret Server:
an onboarding rule and its key, created by a Secret Server administrator,
register a named client account that then exchanges its id and secret for a
token at /oauth2/token (the provider's sdk_client auth mode). The protocol is
two calls, POST /api/v1/sdk-client-accounts and the token grant; tss-sdk-java
is the only public implementation (see docs/research/2026-10-14-delinea/ in
the metabase_security repository).

WHERE EACH VALUE GOES, AND WHY:

  * the onboarding key is read from stdin, never argv, so it is in no process
    listing and no shell history;
  * the client secret is written to stdout and nowhere else: nothing on this
    path holds it in a file, so it can go straight into systemd-creds and be
    sealed to the TPM in the same pipeline;
  * the client id, which is not secret, goes to --client-id-file, because the
    unit needs it in its configuration;
  * diagnostics go to stderr and never contain either secret.

ONCE PER HOST. tss-sdk-java onboards on every start, so client accounts pile
up and the onboarding key becomes the long-lived secret. This onboards when
asked and is never retried: a retry after a timeout could register a second
client. Disable the rule or rotate its key in Secret Server afterwards.

--verify (the default) proves the new client by requesting one token, which
is discarded. Exit status: 0 onboarded, 1 refused or failed, 2 usage.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from typing import Any

from .base import SecretError
from .delinea_client import AUTH_MODES, _json_body, _require_https

_TIMEOUT = 30.0
SDK_CLIENT_PREFIX = "sdk-client-"


def onboard(
    base_url: str,
    rule: str,
    onboarding_key: str,
    name: str,
    description: str = "",
    transport: Any | None = None,
) -> tuple[str, str]:
    """Register one SDK client. Returns (client_id, client_secret)."""
    import httpx

    _require_https(base_url)
    if not onboarding_key:
        raise SecretError("no onboarding key on stdin")
    with httpx.Client(transport=transport, base_url=base_url.rstrip("/"),
                      timeout=_TIMEOUT) as client:
        try:
            response = client.post(
                "/api/v1/sdk-client-accounts",
                json={
                    "OnboardingKey": onboarding_key,
                    "RuleName": rule,
                    "ClientId": str(uuid.uuid4()),
                    "Name": name,
                    "Description": description or f"secops-ingest on {name}",
                },
            )
        except httpx.HTTPError as exc:
            raise SecretError("secret server unreachable during onboarding") from exc
        if response.status_code >= 400:
            # The body can echo the onboarding key. Never include it.
            raise SecretError(
                f"secret server returned {response.status_code} during onboarding; "
                "check the rule name, its key, and any IP restriction on the rule"
            )
        body = _json_body(response, "during onboarding")
        if not isinstance(body, dict):
            raise SecretError("secret server returned no client account")
        client_id = body.get("clientId")
        client_secret = body.get("clientSecret")
        if not isinstance(client_id, str) or not client_id:
            raise SecretError("secret server returned no clientId")
        if not isinstance(client_secret, str) or not client_secret:
            raise SecretError("secret server returned no clientSecret")
    # The token grant names the account sdk-client-<id>.
    if not client_id.startswith(SDK_CLIENT_PREFIX):
        client_id = SDK_CLIENT_PREFIX + client_id
    return client_id, client_secret


def verify(base_url: str, client_id: str, client_secret: str,
           transport: Any | None = None) -> None:
    """Request one token as the new client, and discard it."""
    import httpx

    token_path, extra = AUTH_MODES["sdk_client"]
    with httpx.Client(transport=transport, base_url=base_url.rstrip("/"),
                      timeout=_TIMEOUT) as client:
        try:
            response = client.post(
                token_path,
                data={"grant_type": "client_credentials", "client_id": client_id,
                      "client_secret": client_secret, **extra},
            )
        except httpx.HTTPError as exc:
            raise SecretError("secret server unreachable verifying the new client") from exc
        if response.status_code >= 400:
            raise SecretError(
                f"the new client was registered but its token request returned "
                f"{response.status_code}; check the rule's role and the account in "
                "Secret Server before onboarding again"
            )
        body = _json_body(response, "verifying the new client")
        if not isinstance(body, dict) or not body.get("access_token"):
            raise SecretError("the new client's token request returned no access_token")


def main(argv: list[str] | None = None, stdin: Any = None, stdout: Any = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m secops_ingest.secrets.onboard",
        description="Onboard this host as a Secret Server SDK client. The "
                    "onboarding key is read from stdin; the client secret is "
                    "written to stdout only.",
    )
    parser.add_argument("--url", required=True,
                        help="Secret Server base URL, e.g. https://pam.example.com/SecretServer")
    parser.add_argument("--rule", required=True, help="the onboarding rule's name")
    parser.add_argument("--name", default=os.uname().nodename,
                        help="the client account's name in Secret Server (default: hostname)")
    parser.add_argument("--description", default="")
    parser.add_argument("--client-id-file", required=True,
                        help="where to write the client id (not secret)")
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                        help="skip the token request that proves the new client")
    args = parser.parse_args(argv)

    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    if stdin.isatty():
        print("onboard: pipe the onboarding key on stdin", file=sys.stderr)
        return 2
    key = stdin.readline().strip()
    try:
        client_id, client_secret = onboard(args.url, args.rule, key, args.name,
                                           args.description)
        # Written before verifying: a client that exists but cannot get a token
        # still has to be found, and disabled, in Secret Server by its id.
        with open(args.client_id_file, "w", encoding="utf-8") as handle:
            handle.write(client_id + "\n")
        if args.verify:
            verify(args.url, client_id, client_secret)
    except SecretError as exc:
        print(f"onboard: {exc}", file=sys.stderr)
        return 1
    stdout.write(client_secret)
    stdout.flush()
    print(f"onboard: registered {client_id}; secret written to stdout only",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
