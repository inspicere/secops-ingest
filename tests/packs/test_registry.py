"""Discovery: built-ins merged with entry points, and every way that can go wrong.

The package is not installed during tests (pythonpath = ["src"]), so nothing is
registered under the entry-point group. Tests inject their own.
"""

from __future__ import annotations

import logging

import pytest

from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import ALLOWLIST_ENV, discover
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


def test_duplicate_name_names_both_distributions(caplog: pytest.LogCaptureFixture) -> None:
    eps = [
        _FakeEntryPoint("vendor", _pack(), dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(), dist_name="pack-b"),
    ]
    problems: list[str] = []
    with caplog.at_level(logging.ERROR):
        discover(extra=eps, problems=problems)
    assert "pack-a" in caplog.text and "pack-b" in caplog.text
    assert len(problems) == 1
    assert "pack-a" in problems[0] and "pack-b" in problems[0]


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


def test_collision_between_two_third_party_packs_skips_both_and_keeps_the_rest() -> None:
    # Fatal used to mean every ingest timer, transform and schema emission
    # exited 1 -- built-in sources included -- because of one stale copy of a
    # pack in the venv. Neither claimant is preferred (that would depend on
    # iteration order); both are dropped, and everything else runs.
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor"), dist_name="pack-a"),
        _FakeEntryPoint("other", _pack(name="other"), dist_name="pack-c"),
        _FakeEntryPoint("vendor", _pack(name="vendor"), dist_name="pack-b"),
    ]
    packs = discover(extra=eps)
    assert set(packs) == {"builtin", "other"}


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
    # Both should be tracked; the collision is reported regardless of order,
    # and the compatible one must not slip through as the "winner".
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=9,<10"),
                       dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=0"),
                       dist_name="pack-b"),
    ]
    problems: list[str] = []
    packs = discover(core_version="0.1.0", extra=eps, problems=problems)
    assert "vendor" not in packs
    assert "pack-a" in problems[0] and "pack-b" in problems[0]


def test_compatible_pack_first_then_incompatible_same_name_is_duplicate() -> None:
    # Compatible pack loads first, then incompatible with same name.
    # The collision is reported regardless of order.
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=0"),
                       dist_name="pack-a"),
        _FakeEntryPoint("vendor", _pack(name="vendor", requires=">=9,<10"),
                       dist_name="pack-b"),
    ]
    problems: list[str] = []
    packs = discover(core_version="0.1.0", extra=eps, problems=problems)
    assert "vendor" not in packs
    assert "pack-a" in problems[0] and "pack-b" in problems[0]


def test_incompatible_unique_pack_is_skipped_not_fatal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Regression: incompatible pack with unique name should be skipped gracefully.
    eps = [_FakeEntryPoint("unique", _pack(name="unique", requires=">=9,<10"))]
    with caplog.at_level(logging.WARNING):
        packs = discover(core_version="0.1.0", extra=eps)
    assert "unique" not in packs
    assert "unique" in caplog.text


# -- the allowlist ---------------------------------------------------------------


class _ExplodingEntryPoint(_FakeEntryPoint):
    """Fails the test if anything loads it: refusal must happen before load."""

    def load(self) -> object:
        raise AssertionError(f"{self.name} was loaded despite the allowlist")


def test_unset_allowlist_loads_every_pack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOWLIST_ENV, raising=False)
    packs = discover(extra=[_FakeEntryPoint("vendor", _pack(), dist_name="vendor-pack")])
    assert "vendor" in packs


def test_allowlist_admits_named_distributions_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "Vendor_Pack, other-pack")
    eps = [
        _FakeEntryPoint("vendor", _pack(name="vendor"), dist_name="vendor-pack"),
        _ExplodingEntryPoint("sneaky", _pack(name="sneaky"), dist_name="typosquat"),
    ]
    problems: list[str] = []
    with caplog.at_level(logging.WARNING):
        packs = discover(extra=eps, problems=problems)
    assert set(packs) == {"builtin", "vendor"}
    assert "typosquat" in caplog.text
    assert any("typosquat" in p for p in problems)


def test_empty_allowlist_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A templating slip that renders the variable empty must not mean "all"."""
    monkeypatch.setenv(ALLOWLIST_ENV, "")
    packs = discover(extra=[_ExplodingEntryPoint("vendor", _pack(), dist_name="vendor-pack")])
    assert set(packs) == {"builtin"}


def test_entry_point_with_no_distribution_is_refused_by_an_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "vendor-pack")
    ep = _ExplodingEntryPoint("vendor", _pack())
    ep.dist = None
    assert set(discover(extra=[ep])) == {"builtin"}


def test_loaded_packs_are_logged_with_their_distribution(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ep = _FakeEntryPoint("vendor", _pack(), dist_name="vendor-pack")
    ep.dist.version = "1.4.2"  # type: ignore[attr-defined]
    with caplog.at_level(logging.INFO):
        discover(extra=[ep])
    assert "loaded pack 'vendor' 0.1.0 from vendor-pack 1.4.2" in caplog.text
