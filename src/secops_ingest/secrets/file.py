"""File-based secret provider.

Works unmodified with systemd ``LoadCredential=``, Docker secrets, and
Kubernetes secret volumes, all of which present secrets as one file per name.
"""

from __future__ import annotations

import os
import pathlib

from .base import SecretError, SecretNotFound, SecretProvider


class FileSecretProvider(SecretProvider):
    """Read secrets from one file per name inside a directory.

    Under systemd, point this at ``$CREDENTIALS_DIRECTORY``.
    """

    def __init__(self, directory: str | os.PathLike[str] | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        if directory is None:
            directory = os.environ.get("CREDENTIALS_DIRECTORY") or os.environ.get(
                "SECOPS_SECRETS_DIR"
            )
        if not directory:
            raise SecretError(
                "FileSecretProvider requires a directory "
                "(CREDENTIALS_DIRECTORY or SECOPS_SECRETS_DIR)"
            )
        self._dir = pathlib.Path(directory).resolve()

    def _fetch(self, name: str) -> str:
        # base.validate_name() already rejects separators and traversal, but
        # confinement is re-checked here so this provider is safe even if it is
        # ever called directly.
        path = (self._dir / name).resolve()
        if path.parent != self._dir:
            raise SecretNotFound(name)
        try:
            # Strip only trailing newline: leading/trailing whitespace can be
            # significant in a secret, but editors and `echo` add a newline.
            return path.read_text(encoding="utf-8").rstrip("\n")
        except FileNotFoundError as exc:
            raise SecretNotFound(name) from exc
        except OSError as exc:
            # Message omits the path to avoid disclosing store layout.
            raise SecretError(f"could not read secret: {name}") from exc
