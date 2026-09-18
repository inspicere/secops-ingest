"""`python -m secops_ingest.transform <target>`.

Before this fix, transform/__main__.py caught nothing from all_targets():
a colliding pack installed anywhere made this entry point die with a raw
traceback instead of a one-line, non-zero exit -- and it configured no
logging at all, so registry.py's own `log.exception` for a pack that raised
on load went out through `logging.lastResort`, unformatted and unscrubbed.

These tests need no database: the entry point imports `runner` -- and through
it psycopg -- only when it is about to run a transform, so parsing arguments
and failing on a bad registry stay driver-free. That is deliberate. While the
import sat at module scope this file skipped in every CI run, because CI
installs [dev,http] and [vault,dev] and never the postgres extra.
"""

from __future__ import annotations

import logging

import pytest

from secops_ingest.packs.registry import DuplicatePack, DuplicateTarget
from secops_ingest.transform.__main__ import main


def test_registry_collision_is_a_clean_exit_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> dict[str, object]:
        raise DuplicatePack("pack 'vendor' is registered by both pack-a and pack-b")

    monkeypatch.setattr("secops_ingest.transform.__main__.all_targets", boom)

    assert main(["anything"]) == 1

    captured = capsys.readouterr()
    assert "pack 'vendor' is registered by both pack-a and pack-b" in captured.err


def test_duplicate_target_is_also_a_clean_exit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> dict[str, object]:
        raise DuplicateTarget("transform target 'x' is declared by both 'a' and 'b'")

    monkeypatch.setattr("secops_ingest.transform.__main__.all_targets", boom)

    assert main(["anything"]) == 1

    captured = capsys.readouterr()
    assert "transform target 'x' is declared by both" in captured.err


def test_logging_is_configured_with_the_redacting_filter_before_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression for F6: the handler must be installed before all_targets()
    # runs, not after -- otherwise a pack that raises on load during
    # discovery logs through logging.lastResort instead of through the
    # redacting filter.
    seen_filters_during_discovery: list[bool] = []

    def spy() -> dict[str, object]:
        root = logging.getLogger()
        has_redactor = any(
            f.__class__.__name__ == "RedactingFilter"
            for handler in root.handlers
            for f in handler.filters
        )
        seen_filters_during_discovery.append(has_redactor)
        return {}

    monkeypatch.setattr("secops_ingest.transform.__main__.all_targets", spy)

    # logging.basicConfig is a NO-OP when the root logger already has handlers,
    # and under pytest it always does. Without clearing them the entry point's
    # own configuration never runs and this test asserts nothing about the code
    # -- which is exactly what happened while the file was skipped: it was
    # written, committed, and never executed once. A real `python -m` process
    # starts with an unconfigured root, so clearing reproduces production
    # rather than faking it.
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    root.handlers = []
    try:
        # all_targets() is patched to return no targets, so argparse's `choices`
        # rejects any value passed here -- that failure is fine, it happens
        # after the discovery call this test is checking.
        with pytest.raises(SystemExit):
            main(["anything"])
    finally:
        for installed in root.handlers:
            installed.close()
        root.handlers, root.level = saved_handlers, saved_level

    assert seen_filters_during_discovery == [True]
