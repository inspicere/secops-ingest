"""`python -m secops_ingest.packs list`."""

from __future__ import annotations

import pytest

from secops_ingest.packs.__main__ import main


def test_list_prints_builtin_with_its_sources(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "builtin" in out
    assert "wazuh" in out


def test_list_reports_target_count(capsys: pytest.CaptureFixture[str]) -> None:
    main(["list"])
    assert "targets" in capsys.readouterr().out.lower()
