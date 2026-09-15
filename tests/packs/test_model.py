"""The pack declaration and what it refuses to accept."""

from __future__ import annotations

import pytest

from secops_ingest.packs.model import Pack
from secops_ingest.schema import InvalidIdentifier


def _pack(**overrides: object) -> Pack:
    kwargs: dict[str, object] = {
        "name": "knowbe4",
        "version": "0.1.0",
        "requires_core": ">=0.1,<0.2",
        "sources": {"phisher": "secops_pack_knowbe4.phisher:SOURCE"},
    }
    kwargs.update(overrides)
    return Pack(**kwargs)  # type: ignore[arg-type]


def test_minimal_pack_has_empty_collections() -> None:
    pack = _pack()
    assert pack.targets == ()
    assert pack.dashboards == ()
    assert pack.extras == ()


def test_pack_is_frozen() -> None:
    with pytest.raises(AttributeError):
        _pack().name = "other"  # type: ignore[misc]


@pytest.mark.parametrize("bad", ["Knowbe4", "know-be4", "4knowbe", "", "know be4", "x" * 70])
def test_pack_name_must_be_a_sql_identifier(bad: str) -> None:
    # The name reaches SQL and the CLI, so it reuses the schema module's rule
    # rather than inventing a second one that can drift from it.
    with pytest.raises(InvalidIdentifier):
        _pack(name=bad)


@pytest.mark.parametrize("bad", ["PhishER", "phish-er", "phish.er"])
def test_source_names_must_be_identifiers_too(bad: str) -> None:
    with pytest.raises(InvalidIdentifier):
        _pack(sources={bad: "mod:SOURCE"})


@pytest.mark.parametrize("bad", ["mod", "mod:", ":SOURCE", "", "mod:a:b"])
def test_source_target_must_be_module_colon_attr(bad: str) -> None:
    with pytest.raises(ValueError, match="module:attr"):
        _pack(sources={"phisher": bad})
