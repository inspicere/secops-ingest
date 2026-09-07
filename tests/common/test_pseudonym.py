"""Subject-key pseudonymisation."""

from __future__ import annotations

import pytest

from secops_ingest.common.pseudonym import (
    MIN_SALT_LENGTH,
    SaltTooShort,
    normalise,
    subject_key,
)

SALT = "x" * MIN_SALT_LENGTH


def test_same_person_same_key_across_formatting() -> None:
    """The whole point: one person must hash identically everywhere."""
    variants = [
        "alice.smith@example.com",
        "Alice.Smith@example.com",
        "  alice.smith@example.com  ",
        "ALICE.SMITH@EXAMPLE.COM",
        "alice.smith@example.com\n",
    ]
    keys = {subject_key(v, SALT) for v in variants}
    assert len(keys) == 1


def test_different_people_differ() -> None:
    assert subject_key("a@example.com", SALT) != subject_key("b@example.com", SALT)


def test_salt_changes_every_key() -> None:
    """Documents the consequence: rotating the salt orphans all history."""
    a = subject_key("alice@example.com", SALT)
    b = subject_key("alice@example.com", "y" * MIN_SALT_LENGTH)
    assert a != b


def test_no_plaintext_identifier_in_output() -> None:
    key = subject_key("alice.smith@example.com", SALT)
    assert "alice" not in key and "example" not in key
    assert len(key) == 64
    int(key, 16)                      # hex


@pytest.mark.parametrize("empty", [None, "", "   ", "\n"])
def test_absent_identifier_yields_none(empty) -> None:
    assert subject_key(empty, SALT) is None


def test_short_salt_rejected() -> None:
    with pytest.raises(SaltTooShort):
        subject_key("alice@example.com", "tooshort")


def test_normalise_strips_internal_whitespace() -> None:
    assert normalise(" Alice .Smith@Example.COM ") == "alice.smith@example.com"
