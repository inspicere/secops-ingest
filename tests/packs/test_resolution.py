"""Source addressing: qualified, bare, and ambiguous."""

from __future__ import annotations

import pytest

from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import AmbiguousSource, UnknownSource, resolve_source

ALPHA = Pack(
    name="alpha", version="0.1.0", requires_core=">=0",
    sources={"shared": "alpha.shared:SOURCE", "only_alpha": "alpha.only:SOURCE"},
)
BETA = Pack(
    name="beta", version="0.1.0", requires_core=">=0",
    sources={"shared": "beta.shared:SOURCE"},
)
REGISTRY = {"alpha": ALPHA, "beta": BETA}


def test_qualified_reference_resolves() -> None:
    assert resolve_source("beta.shared", REGISTRY) == "beta.shared:SOURCE"


def test_unambiguous_bare_name_resolves() -> None:
    # This is the compatibility guarantee: existing units pass bare names.
    assert resolve_source("only_alpha", REGISTRY) == "alpha.only:SOURCE"


def test_ambiguous_bare_name_lists_the_candidates() -> None:
    with pytest.raises(AmbiguousSource) as excinfo:
        resolve_source("shared", REGISTRY)
    assert "alpha.shared" in str(excinfo.value)
    assert "beta.shared" in str(excinfo.value)


def test_unknown_bare_name() -> None:
    with pytest.raises(UnknownSource, match="nothing"):
        resolve_source("nothing", REGISTRY)


def test_unknown_pack_in_qualified_name() -> None:
    with pytest.raises(UnknownSource, match="gamma.shared"):
        resolve_source("gamma.shared", REGISTRY)


def test_known_pack_unknown_source() -> None:
    with pytest.raises(UnknownSource, match="beta.missing"):
        resolve_source("beta.missing", REGISTRY)


def test_unknown_source_lists_the_available_qualified_references() -> None:
    # Matches the style of secops_ingest.secrets.get_provider's "available: "
    # message -- a typo like this must not leave the operator guessing.
    with pytest.raises(UnknownSource) as excinfo:
        resolve_source("nothing", REGISTRY)
    message = str(excinfo.value)
    assert "available:" in message
    assert "alpha.shared" in message
    assert "alpha.only_alpha" in message
    assert "beta.shared" in message


def test_unknown_qualified_source_also_lists_availability() -> None:
    # A source belonging to a pack skipped for a version mismatch must read
    # differently from a plain typo -- listing what IS available makes that
    # visible instead of two identical "unknown source" messages.
    with pytest.raises(UnknownSource) as excinfo:
        resolve_source("beta.missing", REGISTRY)
    message = str(excinfo.value)
    assert "available:" in message
    assert "alpha.shared" in message
    assert "beta.shared" in message


def test_builtin_sources_resolve_bare_by_default() -> None:
    # No registry passed: discovery runs, and core's sources must be reachable
    # by the bare names already in production.
    assert resolve_source("wazuh") == "secops_ingest.sources.wazuh:SOURCE"
