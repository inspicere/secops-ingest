"""The startup schema-drift check against a real PostgreSQL.

The unit tests in tests/common/test_schema_check.py prove the message is
assembled as intended, with a mocked cursor. A mock cannot prove PostgreSQL
answers information_schema the way the check assumes, or that a control schema
built by an older package actually trips it -- so this file builds one: the
fixture applies the package's own control DDL minus the posture column, which
is exactly the state the failed upgrade in the incident left behind.

Skipped unless SECOPS_TEST_DSN is set, matching
tests/packs/test_state_integration.py, so `pytest` on a laptop with no server
still passes::

    docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=secops \
        postgres:16
    SECOPS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:5433/secops \
        pytest tests/schema/test_schema_drift_integration.py -v
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

psycopg = pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

pytestmark = pytest.mark.skipif(
    not os.environ.get("SECOPS_TEST_DSN"),
    reason="SECOPS_TEST_DSN is unset; no database to test against",
)

# Deliberately below the importorskip: everything from here on may import
# psycopg, so a missing driver must skip at collection, not error.
from secops_ingest.cli import main as ingest_main  # noqa: E402
from secops_ingest.common import schema_check  # noqa: E402
from secops_ingest.schema import control_sql  # noqa: E402
from secops_ingest.transform.__main__ import main as transform_main  # noqa: E402

# Reused rather than retyped: the evidence-based guard that refuses to drop
# `control` on a database that looks like a real warehouse. A copy here would
# drift from the original the first time someone tightened it.
from tests.packs.test_state_integration import _refuse_if_live  # noqa: E402


def _legacy_control_sql() -> str:
    """The control DDL as the pre-upgrade deployment would have applied it.

    Every line mentioning posture goes: the two column declarations and the
    two migration ALTERs. What remains is a valid, self-consistent older
    control schema -- the exact state CREATE TABLE IF NOT EXISTS leaves behind
    when a newer package starts writing `posture`.
    """
    return "\n".join(
        line for line in control_sql().splitlines() if "posture" not in line
    )


@pytest.fixture()
def drifted() -> Iterator[psycopg.Connection]:
    """A scratch database whose control schema predates the posture column."""
    with psycopg.connect(os.environ["SECOPS_TEST_DSN"]) as conn:
        _refuse_if_live(conn)
        conn.execute("DROP SCHEMA IF EXISTS control CASCADE")
        conn.execute(_legacy_control_sql())
        conn.commit()
        try:
            yield conn
        finally:
            # Leave no control schema behind for the next test file sharing
            # this database. Roll back first: a test that raised inside a
            # transaction leaves the connection aborted, and the teardown's
            # own statement would then raise InFailedSqlTransaction instead of
            # actually cleaning up.
            conn.rollback()
            conn.execute("DROP SCHEMA IF EXISTS control CASCADE")
            conn.commit()


def test_check_names_table_column_and_remedy(drifted: psycopg.Connection) -> None:
    with pytest.raises(schema_check.ControlSchemaDrift) as excinfo:
        schema_check.verify_control_schema(drifted)

    message = str(excinfo.value)
    assert "control.ingest_run" in message
    assert "control.transform_run" in message
    assert "posture" in message
    assert "python -m secops_ingest.schema" in message
    assert "\n" not in message


def test_check_passes_once_the_package_ddl_is_applied(
    drifted: psycopg.Connection,
) -> None:
    drifted.execute(control_sql())
    drifted.commit()
    schema_check.verify_control_schema(drifted)


def test_ingest_cli_refuses_in_one_line_without_a_traceback(
    drifted: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)

    assert ingest_main(["example", "--dry-run"]) == 1

    captured = capsys.readouterr()
    assert "control.ingest_run" in captured.err
    assert "posture" in captured.err
    assert "python -m secops_ingest.schema" in captured.err
    assert "Traceback" not in captured.err


def test_transform_entry_point_refuses_in_one_line_without_a_traceback(
    drifted: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])

    assert transform_main(["xsoar_incidents"]) == 1

    captured = capsys.readouterr()
    assert "control.transform_run" in captured.err
    assert "posture" in captured.err
    assert "python -m secops_ingest.schema" in captured.err
    assert "Traceback" not in captured.err


def test_refusal_happens_before_any_run_ledger_write(
    drifted: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The incident worker died inside its own INSERT, leaving a RUNNING row
    # forever. The check must fire before that INSERT.
    monkeypatch.setenv("SECOPS_DB_DSN", os.environ["SECOPS_TEST_DSN"])
    monkeypatch.delenv("SECOPS_DB_LEASE", raising=False)
    monkeypatch.delenv("SECOPS_SECRETS_BACKEND", raising=False)

    ingest_main(["example", "--dry-run"])

    with drifted.cursor() as cur:
        cur.execute("SELECT count(*) FROM control.ingest_run")
        assert cur.fetchone()[0] == 0
