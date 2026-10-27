"""Build the composite provider from configuration.

`SECOPS_SECRETS_BACKEND=mapped` names the composite, and the composite cannot
exist without a root provider to read its map from. Nothing in the environment
expressed that root, so get_provider("mapped") raised "requires a map_source
provider" on every call and the assured posture could not be switched on from
any entry point. This module is the missing expression:

    SECOPS_SECRETS_MAP_SOURCE   vault_agent | file | env   the root's kind
    SECOPS_SECRETS_MAP_NAME     the map's name in the root (default secret-map)

THE ROOT IS CONFIGURED BY ENVIRONMENT, NOT BY THE MAP, because the map is read
through the root: naming the root inside the document it serves is circular.
It is named explicitly rather than inferred from which variables happen to be
set, so a stray SECOPS_VAULT_AGENT_SOCKET in a unit cannot silently switch
roots. The root's own settings come from the variables each provider already
reads (SECOPS_VAULT_AGENT_SOCKET; CREDENTIALS_DIRECTORY or SECOPS_SECRETS_DIR;
the SECOPS_SECRET_ prefix), so this module adds two variables and no others.
"""

from __future__ import annotations

import os
from typing import Any

from .base import InvalidSecretName, SecretError, SecretProvider, validate_name

#: Kinds that may serve the map. vault_agent bootstraps without a credential in
#: the unit's environment. file and env exist for development and CI, and
#: MappedSecretProvider refuses an 'assured' map served by either: a map that
#: anyone who can write a file can rewrite is not an assured map.
#:
#: Deliberately absent: vault (hvac), which would need a token in the unit's
#: environment, and delinea, which needs a credential of its own and addresses
#: by numeric id, so it cannot serve a map by name. mapped is absent because a
#: composite cannot be its own root.
ROOT_KINDS = ("vault_agent", "file", "env")

DEFAULT_MAP_NAME = "secret-map"


def root_kind_from_environment() -> str:
    """Return SECOPS_SECRETS_MAP_SOURCE, refusing an unset or unknown value."""
    kind = os.environ.get("SECOPS_SECRETS_MAP_SOURCE", "")
    if not kind:
        raise SecretError(
            "SECOPS_SECRETS_BACKEND=mapped requires SECOPS_SECRETS_MAP_SOURCE, one of: "
            f"{', '.join(ROOT_KINDS)}"
        )
    if kind not in ROOT_KINDS:
        raise SecretError(
            f"unknown SECOPS_SECRETS_MAP_SOURCE {kind!r}; expected one of: "
            f"{', '.join(ROOT_KINDS)}"
        )
    return kind


def map_name_from_environment() -> str:
    """Return SECOPS_SECRETS_MAP_NAME, or the default, as a valid secret name."""
    name = os.environ.get("SECOPS_SECRETS_MAP_NAME", "") or DEFAULT_MAP_NAME
    try:
        return validate_name(name)
    except InvalidSecretName as exc:
        # Configuration, not a secret, so the message may quote it.
        raise SecretError(f"SECOPS_SECRETS_MAP_NAME is not a valid secret name: {name!r}") from exc


def mapped_from_environment(
    map_source: SecretProvider | None = None, **kwargs: Any
) -> SecretProvider:
    """The registry's constructor for 'mapped'.

    With `map_source`, behaves exactly as MappedSecretProvider always has, so
    callers that build their own root (tests, the integration suite) are
    unaffected. Without one, builds the root from the environment.
    """
    from .mapped import MappedSecretProvider

    if map_source is not None:
        return MappedSecretProvider(map_source=map_source, **kwargs)

    kind = root_kind_from_environment()
    # Checked before the root is built: a bad map name is a cheaper, clearer
    # failure than whatever the root's construction reports first.
    kwargs.setdefault("map_name", map_name_from_environment())
    from . import get_provider

    # An explicit kind, never a bare get_provider(): with no argument it would
    # read SECOPS_SECRETS_BACKEND, which is 'mapped', and build this again.
    root = get_provider(kind)
    return MappedSecretProvider(map_source=root, root_kind=kind, **kwargs)
