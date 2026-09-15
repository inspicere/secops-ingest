"""The restricted version grammar.

Deliberately narrower than PEP 440: core has no third-party dependencies, so
`packaging` is unavailable and the grammar is what we can parse safely.
"""

from __future__ import annotations

import pytest

from secops_ingest.packs.version import InvalidVersionSpec, matches, parse_version


def test_parse_pads_nothing_and_returns_ints() -> None:
    assert parse_version("0.2.1") == (0, 2, 1)


@pytest.mark.parametrize(
    ("version", "spec"),
    [
        ("0.2.0", ">=0.2,<0.3"),
        ("0.2.9", ">=0.2,<0.3"),
        ("0.2", "==0.2.0"),      # shorter version padded, not rejected
        ("0.2.0", "==0.2"),      # and padding works in both directions
        ("1.0", ">=0"),
    ],
)
def test_satisfied(version: str, spec: str) -> None:
    assert matches(version, spec) is True


@pytest.mark.parametrize(
    ("version", "spec"),
    [
        ("0.3.0", ">=0.2,<0.3"),
        ("0.1.9", ">=0.2,<0.3"),
        ("0.2.1", "==0.2.0"),
    ],
)
def test_not_satisfied(version: str, spec: str) -> None:
    assert matches(version, spec) is False


@pytest.mark.parametrize(
    "spec",
    [
        "~=0.2",          # compatible-release operator is not supported
        ">=0.2rc1",       # pre-releases are not supported
        ">=1!0.2",        # epochs are not supported
        ">=0.2+local",    # local versions are not supported
        "",               # an empty range is a mistake, not "anything"
        ">= ",
        "0.2",            # a bare version is not a range
    ],
)
def test_unsupported_grammar_is_rejected(spec: str) -> None:
    with pytest.raises(InvalidVersionSpec):
        matches("0.2.0", spec)


def test_unparsable_version_is_rejected() -> None:
    with pytest.raises(InvalidVersionSpec):
        matches("0.2.0rc1", ">=0.2")
