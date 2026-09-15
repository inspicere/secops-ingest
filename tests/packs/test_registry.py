"""Discovery: built-ins merged with entry points, and every way that can go wrong.

The package is not installed during tests (pythonpath = ["src"]), so nothing is
registered under the entry-point group. Tests inject their own.
"""

from __future__ import annotations

import logging

import pytest

from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import DuplicatePack, discover
from secops_ingest.packs.version import InvalidVersionSpec


class _FakeEntryPoint:
    """Enough of importlib.metadata.EntryPoint for the registry to use."""

    def __init__(self, name: str, value: object, dist_name: str = "test-dist") -> None:
        self.name = name
        self.value = f"tests.fake:{name}"
        self._value = value
        self.dist = type("Dist", (), {"name": dist_name})()

    def load(self) -> object:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value


def _pack(name: str = "vendor", requires: str = ">=0") -> Pack:
    return Pack(
        name=name,
        version="0.1.0",
        requires_core=requires,
        sources={"thing": "vendor_pack.thing:SOURCE"},
    )


def test_builtin_is_always_present() -> None:
    packs = discover()
    assert "builtin" in packs
    assert set(packs["builtin"].sources) >= {"example", "wazuh", "defectdojo"}


def test_entry_point_pack_is_merged() -> None:
    packs = discover(extra=[_FakeEntryPoint("vendor", _pack())])
    assert set(packs) == {"builtin", "vendor"}


def test_duplicate_name_names_both_distributions() -> None:
    eps = [
        _FakeEntryPoint("vendor", _pack(), dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(), dist_name="pack-b"),
    ]
    with pytest.raises(DuplicatePack) as excinfo:
        discover(extra=eps)
    assert "pack-a" in str(excinfo.value)
    assert "pack-b" in str(excinfo.value)


def test_a_pack_colliding_with_builtin_is_skipped_naming_core_the_winner(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Unlike a third-party/third-party collision, this one must not be fatal:
    # core is seeded before entry points are even looked up, so there is no
    # ordering ambiguity, and a vendor should not be able to take down every
    # ingest timer, transform and schema emission just by naming their pack
    # "builtin".
    with caplog.at_level(logging.ERROR):
        packs = discover(
            extra=[_FakeEntryPoint("builtin", _pack(name="builtin"), dist_name="evil-dist")]
        )
    # Core's own pack won -- not the impostor's, which declares a different
    # source ("thing") that must not have made it in.
    assert "thing" not in packs["builtin"].sources
    assert "wazuh" in packs["builtin"].sources
    assert "evil-dist" in caplog.text
    assert "builtin" in caplog.text


def test_collision_between_two_third_party_packs_is_still_fatal() -> None:
    # F2 narrows the fatal case to third-party/third-party collisions; this
    # pins that the narrowing did not remove the protection entirely.
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor"), dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(name="vendor"), dist_name="pack-b"),
    ]
    with pytest.raises(DuplicatePack) as excinfo:
        discover(extra=eps)
    assert "pack-a" in str(excinfo.value)
    assert "pack-b" in str(excinfo.value)


def test_invalid_core_version_fails_loudly_naming_core_not_a_pack() -> None:
    # A release-candidate tag on core must not be blamed on the first pack in
    # the loop -- it is core's own version that is unusable.
    with pytest.raises(InvalidVersionSpec) as excinfo:
        discover(core_version="0.2.0rc1")
    assert "0.2.0rc1" in str(excinfo.value)


def test_incompatible_pack_is_skipped_not_fatal(caplog: pytest.LogCaptureFixture) -> None:
    # One bad pack must not take out every other pack's timers.
    eps = [
        _FakeEntryPoint("old", _pack(name="old", requires=">=9,<10")),
        _FakeEntryPoint("good", _pack(name="good")),
    ]
    with caplog.at_level(logging.WARNING):
        packs = discover(core_version="0.1.0", extra=eps)
    assert set(packs) == {"builtin", "good"}
    assert "old" in caplog.text


def test_unusable_version_range_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    eps = [_FakeEntryPoint("weird", _pack(name="weird", requires="~=0.2"))]
    with caplog.at_level(logging.ERROR):
        packs = discover(extra=eps)
    assert "weird" not in packs
    assert "weird" in caplog.text


def test_entry_point_that_raises_does_not_abort_discovery(
    caplog: pytest.LogCaptureFixture,
) -> None:
    eps = [
        _FakeEntryPoint("broken", ImportError("no httpx")),
        _FakeEntryPoint("good", _pack(name="good")),
    ]
    with caplog.at_level(logging.ERROR):
        packs = discover(extra=eps)
    assert set(packs) == {"builtin", "good"}
    assert "broken" in caplog.text


def test_entry_point_that_is_not_a_pack_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    eps = [_FakeEntryPoint("wrong", object())]
    with caplog.at_level(logging.ERROR):
        packs = discover(extra=eps)
    assert "wrong" not in packs


def test_incompatible_pack_first_then_compatible_same_name_is_duplicate() -> None:
    # Incompatible pack loads first, then compatible with same name.
    # Both should be tracked; duplicate should raise regardless of order.
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=9,<10"),
                       dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=0"),
                       dist_name="pack-b"),
    ]
    with pytest.raises(DuplicatePack) as excinfo:
        discover(core_version="0.1.0", extra=eps)
    assert "pack-a" in str(excinfo.value)
    assert "pack-b" in str(excinfo.value)


def test_compatible_pack_first_then_incompatible_same_name_is_duplicate() -> None:
    # Compatible pack loads first, then incompatible with same name.
    # Collision should raise regardless of order.
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=0"),
                       dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=9,<10"),
                       dist_name="pack-b"),
    ]
    with pytest.raises(DuplicatePack) as excinfo:
        discover(core_version="0.1.0", extra=eps)
    assert "pack-a" in str(excinfo.value)
    assert "pack-b" in str(excinfo.value)


def test_incompatible_unique_pack_is_skipped_not_fatal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Regression: incompatible pack with unique name should be skipped gracefully.
    eps = [_FakeEntryPoint("unique", _pack(name="unique", requires=">=9,<10"))]
    with caplog.at_level(logging.WARNING):
        packs = discover(core_version="0.1.0", extra=eps)
    assert "unique" not in packs
    assert "unique" in caplog.text
