"""Tests for jsonb-safe payload serialisation.

A single NUL character in a captured scanner banner aborted a 50,000-record
backfill, hours in, having written nothing for that run. These pin the fix and,
more importantly, the reason it is done on the object rather than the text.
"""

from __future__ import annotations

import json

import pytest

from secops_ingest.common.payload import strip_nuls, to_json


def test_nul_is_removed_from_a_string() -> None:
    out = to_json({"banner": "Server: RomPager/4.62\r\n\x00"})
    assert "\\u0000" not in out
    assert json.loads(out)["banner"] == "Server: RomPager/4.62\r\n"


def test_nul_is_removed_at_every_depth() -> None:
    """Scanner output nests: findings carry lists of endpoints carrying banners."""
    record = {"a": {"b": [{"c": "x\x00y"}]}, "d": ["p\x00q"]}
    loaded = json.loads(to_json(record))
    assert loaded["a"]["b"][0]["c"] == "xy"
    assert loaded["d"] == ["pq"]


def test_a_literal_backslash_u_sequence_is_preserved() -> None:
    """The reason stripping happens BEFORE serialisation, not after.

    Editing the six-character escape out of the JSON text cannot distinguish an
    escaped NUL from a string that genuinely contains those characters, so the
    naive text replacement corrupts data it was never meant to touch.
    """
    # Built rather than written literally: a source file containing a real NUL
    # cannot be parsed at all.
    literal = chr(92) + "u0000"
    record = {"note": f"the escape {literal} means NUL"}
    out = to_json(record)
    assert json.loads(out)["note"] == f"the escape {literal} means NUL"
    assert chr(0) not in json.loads(out)["note"]


def test_clean_records_are_untouched() -> None:
    record = {"id": 7, "severity": "High", "tags": ["a", "b"], "score": 3.1, "ok": True}
    assert json.loads(to_json(record)) == record


def test_non_string_values_survive_stripping() -> None:
    record = {"i": 1, "f": 1.5, "b": False, "n": None}
    assert strip_nuls(record) == record


def test_stripping_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Silently altering stored data must not be invisible.

    Someone comparing a warehouse row against the vendor's UI needs a way to
    find out why they differ.
    """
    with caplog.at_level("WARNING"):
        to_json({"x": "a\x00b"}, identifier="finding-42")
    assert "finding-42" in caplog.text
    assert "NUL" in caplog.text


def test_clean_records_log_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        to_json({"x": "clean"}, identifier="finding-43")
    assert caplog.text == ""


def test_output_is_always_valid_json() -> None:
    for record in ({"a": "\x00"}, {"a": ["\x00", {"b": "\x00"}]}, {"a": "plain"}):
        json.loads(to_json(record))
