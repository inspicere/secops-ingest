"""File-based secret provider.

Works unmodified with systemd ``LoadCredential=``, Docker secrets, and
Kubernetes secret volumes, all of which present secrets as one file per name.
"""

from __future__ import annotations

import logging
import os
import pathlib
import stat
from typing import ClassVar

from .base import SecretError, SecretNotFound, SecretProvider
from .mapping import Posture

log = logging.getLogger(__name__)


class FileSecretProvider(SecretProvider):
    """Read secrets from one file per name inside a directory.

    Under systemd, point this at ``$CREDENTIALS_DIRECTORY``.
    """

    #: A file on the host is not a PAM. Declared so that a run resolving through this
    #: provider records 'dev' rather than NULL: NULL reads as "not declared",
    #: and this provider's posture is known.
    posture: ClassVar[Posture] = Posture.DEV

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
        #
        # Judged by where the name lands, not by its parent: Kubernetes secret
        # volumes link `name -> ..data/name` and `..data -> ..<timestamp>/`, so
        # a resolved secret sits one directory below this one. Requiring the
        # parent to equal the directory reported every such secret as missing.
        # Anything that resolves outside the directory is still refused.
        path = (self._dir / name).resolve()
        if path == self._dir or not path.is_relative_to(self._dir):
            raise SecretNotFound(name)
        try:
            with path.open(encoding="utf-8") as handle:
                self._warn_if_world_readable(name, os.fstat(handle.fileno()).st_mode)
                # Strip only trailing newline: leading/trailing whitespace can
                # be significant in a secret, but editors and `echo` add one.
                return handle.read().rstrip("\n")
        except FileNotFoundError as exc:
            raise SecretNotFound(name) from exc
        except OSError as exc:
            # Message omits the path to avoid disclosing store layout.
            raise SecretError(f"could not read secret: {name}") from exc

    @staticmethod
    def _warn_if_world_readable(name: str, mode: int) -> None:
        """Say so when any user on the host can read or rewrite a secret file.

        A warning, not a refusal. Docker secrets (0444) and Kubernetes secret
        volumes (0644 by default) are world-readable inside a container where
        nobody else runs, and refusing them would take those deployments
        down. On a shared host it is a real exposure, and the run should say
        it is running with one rather than read the file without comment.
        Checked on the open handle, so it describes the file actually read.
        """
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            log.warning(
                "secret file for %s is open to every user on the host (mode %03o); "
                "restrict it to 0640 or tighter",
                name,
                stat.S_IMODE(mode),
            )
