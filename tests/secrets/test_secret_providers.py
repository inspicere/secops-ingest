"""Tests for the secret provider abstraction.

No live backend is contacted. Delinea and Vault providers are exercised only
for their construction and error paths.
"""

from __future__ import annotations

import logging
import pathlib

import pytest

from secops_ingest.redaction import RedactingFilter
from secops_ingest.secrets import (
    EnvSecretProvider,
    FileSecretProvider,
    InvalidSecretName,
    SecretError,
    SecretNotFound,
    get_provider,
    validate_name,
)

# --- name validation: this is what makes path-based backends safe ---

@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/shadow",
        "a/b",
        "a\\b",
        "",
        ".",
        "..",
        "/absolute",
        "name\x00null",
        "x" * 200,
    ],
)
def test_invalid_names_rejected(bad: str) -> None:
    with pytest.raises(InvalidSecretName):
        validate_name(bad)


@pytest.mark.parametrize("good", ["wazuh-indexer-password", "indexer.key", "a", "A_1-b.c"])
def test_valid_names_accepted(good: str) -> None:
    assert validate_name(good) == good


# --- env provider ---

def test_env_provider_reads_and_maps_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_SECRET_WAZUH_INDEXER_PASSWORD", "tok-123")
    assert EnvSecretProvider().get("wazuh-indexer-password") == "tok-123"


def test_env_provider_missing_raises_without_leaking_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECOPS_SECRET_NOPE", raising=False)
    with pytest.raises(SecretNotFound) as exc:
        EnvSecretProvider().get("nope")
    assert "SECOPS_SECRET" not in str(exc.value)


# --- file provider ---

def test_file_provider_reads(tmp_path: pathlib.Path) -> None:
    (tmp_path / "xdr-api-key").write_text("key-abc\n")
    assert FileSecretProvider(tmp_path).get("xdr-api-key") == "key-abc"


def test_file_provider_preserves_internal_whitespace(tmp_path: pathlib.Path) -> None:
    (tmp_path / "tok").write_text("a b\n")
    assert FileSecretProvider(tmp_path).get("tok") == "a b"


def test_file_provider_rejects_traversal(tmp_path: pathlib.Path) -> None:
    outside = tmp_path.parent / "outside-secret"
    outside.write_text("should-not-be-readable")
    provider = FileSecretProvider(tmp_path / "store")
    (tmp_path / "store").mkdir(exist_ok=True)
    with pytest.raises(InvalidSecretName):
        provider.get("../outside-secret")


def test_file_provider_missing_raises(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SecretNotFound):
        FileSecretProvider(tmp_path).get("absent")


def test_file_provider_follows_a_kubernetes_secret_volume(tmp_path: pathlib.Path) -> None:
    # Kubernetes links name -> ..data/name and ..data -> ..<timestamp>/, so the
    # resolved file sits one level below the directory. It used to be reported
    # as missing because its parent was not the directory itself.
    stamp = tmp_path / "..2026_10_25_00_00_00.123"
    stamp.mkdir()
    (stamp / "db-pass").write_text("k8s-volume-value\n")
    (tmp_path / "..data").symlink_to(stamp.name)
    (tmp_path / "db-pass").symlink_to("..data/db-pass")
    assert FileSecretProvider(tmp_path).get("db-pass") == "k8s-volume-value"


def test_file_provider_refuses_a_symlink_out_of_the_directory(tmp_path: pathlib.Path) -> None:
    store = tmp_path / "store"
    store.mkdir()
    (tmp_path / "elsewhere").write_text("not-a-secret-of-ours")
    (store / "tok").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(SecretNotFound):
        FileSecretProvider(store).get("tok")


def test_file_provider_warns_on_a_world_readable_secret(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "tok"
    path.write_text("world-readable-value")
    path.chmod(0o644)
    with caplog.at_level(logging.WARNING, logger="secops_ingest.secrets.file"):
        # A warning, not a refusal: Docker and Kubernetes ship secrets this way.
        assert FileSecretProvider(tmp_path).get("tok") == "world-readable-value"
    assert "tok" in caplog.text and "644" in caplog.text
    assert str(tmp_path) not in caplog.text
    assert "world-readable-value" not in caplog.text


def test_file_provider_is_quiet_about_a_private_secret(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "tok"
    path.write_text("private-value")
    path.chmod(0o640)
    with caplog.at_level(logging.WARNING, logger="secops_ingest.secrets.file"):
        FileSecretProvider(tmp_path).get("tok")
    assert caplog.text == ""


@pytest.mark.parametrize("content", ["", "\n", "  \n"])
def test_an_empty_secret_is_refused(tmp_path: pathlib.Path, content: str) -> None:
    # A truncated write would otherwise be sent to the vendor as the credential.
    (tmp_path / "tok").write_text(content)
    with pytest.raises(SecretError, match="secret is empty: tok"):
        FileSecretProvider(tmp_path).get("tok")


def test_an_empty_env_secret_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_SECRET_TOK", "")
    with pytest.raises(SecretError, match="secret is empty: tok") as exc:
        EnvSecretProvider().get("tok")
    assert not isinstance(exc.value, SecretNotFound)


def test_file_provider_uses_systemd_credentials_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "tok").write_text("v")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert FileSecretProvider().get("tok") == "v"


# --- caching ---

def test_cache_avoids_refetch(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "tok"
    p.write_text("first")
    provider = FileSecretProvider(tmp_path)
    assert provider.get("tok") == "first"
    p.write_text("second")
    assert provider.get("tok") == "first"      # served from cache
    provider.clear_cache()
    assert provider.get("tok") == "second"


def test_cache_can_be_disabled(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "tok"
    p.write_text("first")
    provider = FileSecretProvider(tmp_path, cache=False)
    assert provider.get("tok") == "first"
    p.write_text("second")
    assert provider.get("tok") == "second"


# --- factory ---

def test_factory_defaults_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)
    assert isinstance(get_provider(), EnvSecretProvider)


def test_factory_unknown_backend_lists_available() -> None:
    with pytest.raises(SecretError) as exc:
        get_provider("does-not-exist")
    assert "available:" in str(exc.value)


def test_factory_honours_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_SECRETS_BACKEND", "file")
    monkeypatch.setenv("SECOPS_SECRETS_DIR", str(tmp_path))
    assert isinstance(get_provider(), FileSecretProvider)


# --- repr must never leak ---

def test_repr_does_not_leak_configuration(tmp_path: pathlib.Path) -> None:
    r = repr(FileSecretProvider(tmp_path))
    assert str(tmp_path) not in r


# --- redaction filter ---

def test_redacting_filter_scrubs_values(caplog: pytest.LogCaptureFixture) -> None:
    redactor = RedactingFilter()
    redactor.register("super-secret-token-value")
    logger = logging.getLogger("t")
    logger.addFilter(redactor)
    with caplog.at_level(logging.INFO, logger="t"):
        logger.info("auth failed for super-secret-token-value")
    assert "super-secret-token-value" not in caplog.text
    assert "***REDACTED***" in caplog.text


def test_redacting_filter_ignores_short_values(caplog: pytest.LogCaptureFixture) -> None:
    redactor = RedactingFilter()
    redactor.register("abc")           # below MIN_LENGTH
    logger = logging.getLogger("t2")
    logger.addFilter(redactor)
    with caplog.at_level(logging.INFO, logger="t2"):
        logger.info("abc appears here")
    assert "abc appears here" in caplog.text
