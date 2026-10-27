"""Every core provider declares its posture, so a run row is never NULL by omission.

Measured before this change: 183 of 183 ingest runs recorded posture NULL,
because production runs SECOPS_SECRETS_BACKEND=file and only the composite
declared a posture. NULL reads as "not declared", which hid exactly the fact
the column exists to show -- that those runs resolved from files on disk.
"""

from __future__ import annotations

from secops_ingest.common.posture import current_posture
from secops_ingest.secrets import EnvSecretProvider, FileSecretProvider
from secops_ingest.secrets.mapping import Posture


def test_the_env_provider_records_dev() -> None:
    assert current_posture(EnvSecretProvider()) == "dev"


def test_the_file_provider_records_dev(tmp_path) -> None:
    assert current_posture(FileSecretProvider(directory=tmp_path)) == "dev"


def test_the_declaration_is_the_posture_enum_not_a_bare_string() -> None:
    # current_posture reads `.value`; a bare "dev" would also pass the two tests
    # above, so pin the type the mapping layer uses.
    assert EnvSecretProvider.posture is Posture.DEV
    assert FileSecretProvider.posture is Posture.DEV


def test_no_provider_is_still_undeclared() -> None:
    # The static-DSN case: no backend named, nothing to claim.
    assert current_posture(None) is None
