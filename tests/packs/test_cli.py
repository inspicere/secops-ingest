"""`python -m secops_ingest.packs list`."""

from __future__ import annotations

from typing import Self

import pytest

from secops_ingest.packs.__main__ import main
from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import discover


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


def _vendor_pack(name: str = "vendor") -> Pack:
    return Pack(
        name=name, version="0.1.0", requires_core=">=0",
        sources={"thing": "vendor_pack.thing:SOURCE"},
    )


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


def test_list_says_state_is_unknown_without_a_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The property this task is most likely to break. `list` is the command
    # you reach for when the install is broken; it must not need the thing
    # that might be broken.
    monkeypatch.delenv("SECOPS_DB_DSN", raising=False)
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "builtin" in out
    assert "unknown" in out.lower()


def test_list_labels_a_connection_failure_as_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A DSN that cannot even be connected to must be labelled as such.

    No real database involved -- `psycopg.connect` is stubbed to raise
    directly, so this never leaves the process.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    def _boom(dsn: str) -> None:
        raise psycopg.OperationalError("could not translate host name")

    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://unreachable/db")
    monkeypatch.setattr(psycopg, "connect", _boom)

    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "builtin" in out
    assert "could not connect" in out.lower()
    assert "could not read" not in out.lower()


def test_list_labels_a_query_failure_as_a_read_problem_not_a_connect_problem(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A reachable database that then refuses the query is a different failure.

    This is the bug the reviewer caught: a successful connect followed by a
    permission-denied read (e.g. USAGE on `control` but no SELECT on
    `control.pack`) was being reported as "could not connect", which points
    an operator at the network/host/DSN when the actual fix is a GRANT. No
    real database is needed here either -- `psycopg.connect` returns a stub
    connection, and `all_states` is made to raise directly.
    """
    psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

    class _StubConn:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc_info: object) -> bool:
            return False

    def _boom(conn: object) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for table pack")

    monkeypatch.setenv("SECOPS_DB_DSN", "postgresql://reachable/db")
    monkeypatch.setattr(psycopg, "connect", lambda dsn: _StubConn())
    monkeypatch.setattr("secops_ingest.packs.state.all_states", _boom)

    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "builtin" in out
    assert "could not read" in out.lower()
    assert "could not connect" not in out.lower()


def test_collision_duplicate_pack_exits_with_code_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real collision between two third-party packs exits clean, code 1.

    Goes through actual discovery (via the injectable `extra` entry points)
    rather than hand-writing the message discover() would produce, so this
    test breaks the moment the real message changes -- not the other way
    around.
    """
    eps = [
        _FakeEntryPoint("vendor", _vendor_pack(), dist_name="pack-a"),
        _FakeEntryPoint("vendor", _vendor_pack(), dist_name="pack-b"),
    ]
    monkeypatch.setattr(
        "secops_ingest.packs.__main__.discover", lambda: discover(extra=eps)
    )

    assert main(["list"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "pack 'vendor' is registered by both" in captured.err
    assert "pack-a" in captured.err
    assert "pack-b" in captured.err
