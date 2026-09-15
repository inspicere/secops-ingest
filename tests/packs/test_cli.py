"""`python -m secops_ingest.packs list`."""

from __future__ import annotations

from typing import Any

import pytest

from secops_ingest.packs.__main__ import main
from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import DuplicatePack, discover


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


def test_list_builtin_structure(capsys: pytest.CaptureFixture[str]) -> None:
    """Output contains builtin pack with correct sources and targets."""
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    lines = out.split("\n")

    # Find the builtin header line.
    builtin_idx = None
    for i, line in enumerate(lines):
        if line.startswith("builtin "):
            builtin_idx = i
            break

    assert builtin_idx is not None, "builtin pack header not found"

    # Next two lines should be sources and targets.
    sources_line = lines[builtin_idx + 1]
    targets_line = lines[builtin_idx + 2]

    # Verify structure: sources line should contain all three sources.
    assert sources_line.strip().startswith("sources:")
    assert "defectdojo" in sources_line
    assert "example" in sources_line
    assert "wazuh" in sources_line

    # Verify targets line is not empty and contains expected targets.
    assert targets_line.strip().startswith("targets:")
    assert "defectdojo_findings" in targets_line
    assert "example_messages" in targets_line
    assert "wazuh_alerts" in targets_line
    assert targets_line.strip() != "targets: -", "targets should not be empty"


def test_collision_duplicate_pack_exits_with_code_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Duplicate pack name exits with code 1 and prints error to stderr."""
    # Create a fake pack with the same name as builtin.
    def fake_discover(**kwargs: Any) -> dict[str, Pack]:
        real_packs = discover(**kwargs)
        # Simulate a collision by adding a second "builtin" pack.
        fake_pack = Pack(
            name="builtin",
            version="0.2.0",
            requires_core=">=0",
            sources={},
            targets=[],
        )
        real_packs["builtin"] = fake_pack
        # This would normally raise DuplicatePack, but we can't easily trigger
        # that without going through entry points. Instead, use monkeypatch.
        raise DuplicatePack(
            "pack 'builtin' is registered by both secops-ingest (core) and "
            "test-dist"
        )

    monkeypatch.setattr("secops_ingest.packs.__main__.discover", fake_discover)

    # Call main and verify exit code is 1.
    assert main(["list"]) == 1

    # Verify error message went to stderr, not stdout.
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "pack 'builtin' is registered by both" in captured.err
    assert "secops-ingest (core)" in captured.err
    assert "test-dist" in captured.err
