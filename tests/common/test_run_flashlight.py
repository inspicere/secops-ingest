"""A lost dependency dims the run; it does not darken it, and it says so.

Each test here pins one way execute() used to go dark or go quiet:

  * the warehouse, a revoked credential or a failed run produced no structured
    event, so nothing outside the warehouse could report the warehouse;
  * a stop raised inside fetch() (with_retries' stop hook) has to end the run
    as a stop, not as a failure;
  * a source that read less than it was asked to (a short KSAT walk, a paging
    gap) recorded a clean SUCCESS;
  * a long non-snapshot scan persisted a watermark past records it had already
    passed and that changed behind it;
  * one malformed record failed every run of the source until a code change;
  * a killed run's RUNNING row was never closed;
  * the in-process deadline and the unit's cap were set in different places
    and disagreed;
  * a secret provider that could not be built left no ledger row at all.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("psycopg", reason="needs the 'postgres' extra")

from secops_ingest.common import context, obs  # noqa: E402
from secops_ingest.common import run as run_mod  # noqa: E402
from secops_ingest.common.schema_check import ControlSchemaDrift  # noqa: E402


class _FakeConn:
    def __init__(self) -> None:
        self.rollbacks = 0

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def rollback(self) -> None:
        self.rollbacks += 1


class _Source:
    name = "wazuh"
    table = "raw_wazuh.alerts"

    def __init__(self, marks: list[Any], *, ordered: bool = True,
                 during: Any = None) -> None:
        self.marks = marks
        self.fetch_order_is_watermark_order = ordered
        self.during = during          # called after the first record, inside fetch

    def authenticate(self) -> object:
        return object()

    def fetch(self, creds: object, cursor: str | None) -> Any:
        for i, mark in enumerate(self.marks):
            yield {"mark": mark}
            if i == 0 and self.during:
                self.during()

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        return (str(record["mark"]), None, record["mark"], run_id)

    def watermark_of(self, record: dict[str, Any]) -> Any:
        if record["mark"] is None:
            raise KeyError("timestamp")
        return record["mark"]


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    conn = _FakeConn()
    calls: dict[str, Any] = {"conn": conn, "watermarks": [], "finished": [],
                             "reaped": [], "started": []}

    def start_run(conn: object, source: str, **kw: Any) -> int:
        calls["started"].append(source)
        return 7

    def finish_run(conn: object, run_id: int, status: str, read: int,
                   written: int, err: Any = None) -> None:
        calls["finished"].append((status, read, written, err))

    def reap(conn: object, source: str, age: int) -> int:
        calls["reaped"].append((source, age))
        return 0

    for var in ("SECOPS_INGEST_DEADLINE_SEC", "SECOPS_INGEST_UNIT_CAP_SEC",
                "SECOPS_INGEST_MAX_REJECTS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(run_mod.db, "connect", lambda provider=None: conn)
    monkeypatch.setattr(run_mod.schema_check, "verify_control_schema", lambda conn: None)
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "start_run", start_run)
    monkeypatch.setattr(run_mod.db, "reap_abandoned", reap)
    monkeypatch.setattr(run_mod.db, "get_watermark", lambda conn, name: None)
    monkeypatch.setattr(run_mod.db, "upsert_many", lambda conn, table, rows: len(list(rows)))
    monkeypatch.setattr(run_mod.db, "set_watermark",
                        lambda conn, src, val: calls["watermarks"].append(val))
    monkeypatch.setattr(run_mod.db, "finish_run", finish_run)
    return calls


def _events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


T1, T2, T3 = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"


# -- V-01: events --------------------------------------------------------------

def test_a_clean_run_announces_its_start_and_its_outcome(
    harness: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    run_mod.execute(_Source([T1, T2]), batch_size=10, deadline_sec=3600)

    events = _events(capsys)
    assert [e["event"] for e in events] == [
        obs.RUN_START, obs.WATERMARK_ADVANCED, obs.RUN_OK,
    ]
    assert events[-1]["rows_written"] == 2 and events[-1]["run_id"] == 7


def test_an_unreachable_warehouse_is_announced_though_no_row_can_be_written(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The case the ledger can never record: it lives in the warehouse."""
    def refuse(provider: object = None) -> Any:
        raise OSError('connection to server at "wh" failed: password authentication failed')

    monkeypatch.setattr(run_mod.db, "connect", refuse)
    with pytest.raises(OSError):
        run_mod.execute(_Source([T1]))

    (event,) = _events(capsys)
    assert event["event"] == obs.WAREHOUSE_UNREACHABLE
    assert event["severity"] == "CRITICAL" and event["source"] == "wazuh"
    assert "password authentication failed" in event["error"]


def test_a_failed_run_is_announced_with_its_scrubbed_reason(
    harness: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from secops_ingest.redaction import register_secret

    register_secret("hunter2-but-longer")

    class _Broken(_Source):
        def authenticate(self) -> object:
            raise RuntimeError("vendor said no to hunter2-but-longer")

    with pytest.raises(RuntimeError):
        run_mod.execute(_Broken([T1]))

    failed = [e for e in _events(capsys) if e["event"] == obs.RUN_FAILED]
    assert len(failed) == 1 and failed[0]["run_id"] == 7
    assert "hunter2-but-longer" not in failed[0]["error"]
    assert harness["finished"][-1][0] == "FAILED"


def test_schema_drift_is_announced(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def drift(conn: object) -> None:
        raise ControlSchemaDrift("control.ingest_run lacks posture; run the schema")

    monkeypatch.setattr(run_mod.schema_check, "verify_control_schema", drift)
    with pytest.raises(ControlSchemaDrift):
        run_mod.execute(_Source([T1]))
    assert [e["event"] for e in _events(capsys)] == [obs.SCHEMA_DRIFT]


def test_an_observability_failure_never_fails_the_run(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_print(*a: Any, **k: Any) -> None:
        raise OSError("stdout is gone")

    monkeypatch.setattr("builtins.print", broken_print)
    result = run_mod.execute(_Source([T1]), deadline_sec=3600)
    assert result.status == "SUCCESS"


def test_emit_survives_a_field_that_cannot_be_rendered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Hostile:
        def __str__(self) -> str:
            raise RuntimeError("no")

        __repr__ = __str__

    rec = obs.emit(obs.RUN_FAILED, "s", error=_Hostile())
    assert rec["event"] == obs.RUN_FAILED
    (event,) = _events(capsys)
    assert event["obs_error"]


# -- V-17: a stop inside fetch() ---------------------------------------------------

def test_a_stop_raised_inside_fetch_ends_the_run_as_a_stop(
    harness: dict[str, Any]
) -> None:
    """with_retries raises StopRequested; the run lands, notes it, advances if ordered."""
    def stop_inside() -> None:
        raise context.StopRequested("SIGTERM")

    result = run_mod.execute(_Source([T1, T2], during=stop_inside), deadline_sec=3600)

    assert result.status == "SUCCESS"
    assert harness["watermarks"] == [T1]
    status, read, written, note = harness["finished"][-1]
    assert (status, read, written) == ("SUCCESS", 1, 1)
    assert "SIGTERM" in note


def test_the_stop_check_is_visible_inside_fetch(harness: dict[str, Any]) -> None:
    seen: list[Any] = []
    src = _Source([T1, T2], during=lambda: seen.append(
        (context.source_name(), context.run_id(), context.stop_reason())))
    run_mod.execute(src, deadline_sec=3600)
    assert seen == [("wazuh", 7, None)]


# -- V-17: reaping abandoned RUNNING rows --------------------------------------------

def test_abandoned_rows_are_reaped_at_the_unit_cap(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_INGEST_UNIT_CAP_SEC", "3600")
    run_mod.execute(_Source([T1]))
    assert harness["reaped"] == [("wazuh", 3600)]


def test_without_a_stated_cap_the_shipped_cap_is_assumed(harness: dict[str, Any]) -> None:
    run_mod.execute(_Source([T1]), deadline_sec=1500)
    assert harness["reaped"] == [("wazuh", 1800)]


def test_with_no_deadline_and_no_cap_nothing_is_reaped(harness: dict[str, Any]) -> None:
    run_mod.execute(_Source([T1]), deadline_sec=-1)
    assert harness["reaped"] == []


def test_a_reap_that_fails_does_not_fail_the_run(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(*a: Any) -> int:
        raise PermissionError("permission denied for table ingest_run")

    monkeypatch.setattr(run_mod.db, "reap_abandoned", denied)
    assert run_mod.execute(_Source([T1]), deadline_sec=3600).status == "SUCCESS"
    assert harness["conn"].rollbacks == 1


def test_a_dry_run_reaps_nothing(harness: dict[str, Any]) -> None:
    run_mod.execute(_Source([T1]), dry_run=True, deadline_sec=3600)
    assert harness["reaped"] == []


def test_reap_abandoned_is_scoped_to_one_source_and_closes_as_failed() -> None:
    from secops_ingest.common import db

    class _Cur:
        rowcount = 2

        def __enter__(self) -> _Cur:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def execute(self, sql: str, params: tuple[Any, ...]) -> None:
            self.sql, self.params = sql, params

    class _Conn:
        commits = 0
        cur = _Cur()

        def cursor(self) -> _Cur:
            return self.cur

        def commit(self) -> None:
            self.commits += 1

    conn = _Conn()
    assert db.reap_abandoned(conn, "defectdojo", 3600) == 2  # type: ignore[arg-type]
    assert "status = 'FAILED'" in conn.cur.sql and "status = 'RUNNING'" in conn.cur.sql
    assert "source = %s" in conn.cur.sql
    note, source, age = conn.cur.params
    assert (source, age) == ("defectdojo", 3600) and note.startswith("abandoned")
    assert conn.commits == 1


# -- V-04: the deadline and the unit's cap -------------------------------------

@pytest.mark.parametrize(
    ("deadline", "cap", "expected"),
    [
        (None, None, 1500),        # nothing said: the shipped default
        ("900", None, 900),        # deadline only: as given
        (None, "3600", 3300),      # cap only: raising the cap is enough
        ("1500", "3600", 1500),    # both, consistent: as given
        ("3600", "3600", 3300),    # deadline at the cap: clamped
        ("1500", "1200", 900),     # cap BELOW the deadline: clamped, not killed
        ("-1", "1800", 1500),      # "no deadline" under a cap: clamped
        (None, "400", 300),        # a small cap keeps a quarter as margin
    ],
)
def test_the_deadline_is_kept_below_the_unit_cap(
    monkeypatch: pytest.MonkeyPatch, deadline: str | None, cap: str | None,
    expected: int,
) -> None:
    for var, value in (("SECOPS_INGEST_DEADLINE_SEC", deadline),
                       ("SECOPS_INGEST_UNIT_CAP_SEC", cap)):
        if value is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, value)
    assert run_mod.resolve_deadline() == expected


def test_a_clamped_deadline_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SECOPS_INGEST_DEADLINE_SEC", "3600")
    monkeypatch.setenv("SECOPS_INGEST_UNIT_CAP_SEC", "3600")
    run_mod.resolve_deadline()
    assert "SECOPS_INGEST_UNIT_CAP_SEC" in caplog.text


def test_a_malformed_deadline_is_refused_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPS_INGEST_UNIT_CAP_SEC", "1h")
    with pytest.raises(ValueError, match="SECOPS_INGEST_UNIT_CAP_SEC"):
        run_mod.resolve_deadline()


# -- V-34 / V-09: a source that reports itself incomplete ------------------------

def test_an_incomplete_unordered_run_keeps_its_cursor_and_says_so(
    harness: dict[str, Any]
) -> None:
    """KSAT's short walk: a WARNING line and a clean SUCCESS, before."""
    src = _Source([T1, T2], ordered=False,
                  during=lambda: context.report_partial("collected 1 of 2"))
    run_mod.execute(src, deadline_sec=3600)

    assert harness["watermarks"] == []
    status, _read, _written, note = harness["finished"][-1]
    assert status == "SUCCESS" and "collected 1 of 2" in note and "kept" in note


def test_an_incomplete_ordered_run_advances_over_what_it_read(
    harness: dict[str, Any]
) -> None:
    """XDR/XSOAR stop before the page that may be shifted, then advance to it."""
    src = _Source([T1, T2], during=lambda: context.report_partial("window shrank"))
    run_mod.execute(src, deadline_sec=3600)
    assert harness["watermarks"] == [T2]
    assert "window shrank" in harness["finished"][-1][3]


# -- V-08: a watermark ceiling -------------------------------------------------

def test_the_persisted_watermark_never_exceeds_the_sources_ceiling(
    harness: dict[str, Any]
) -> None:
    src = _Source([T3, T1], ordered=False, during=lambda: context.cap_watermark(T2))
    run_mod.execute(src, deadline_sec=3600)
    assert harness["watermarks"] == [T2]


def test_a_ceiling_above_everything_seen_changes_nothing(harness: dict[str, Any]) -> None:
    src = _Source([T1, T2], during=lambda: context.cap_watermark(T3))
    run_mod.execute(src, deadline_sec=3600)
    assert harness["watermarks"] == [T2]


# -- V-34: malformed records -----------------------------------------------------

def test_a_malformed_record_is_skipped_counted_and_announced(
    harness: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    result = run_mod.execute(_Source([T1, None, T2]), deadline_sec=3600)

    assert (result.status, result.rows_read, result.rows_written) == ("SUCCESS", 3, 2)
    assert harness["watermarks"] == [T2]
    note = harness["finished"][-1][3]
    assert "rejected 1 malformed record(s) (KeyError x1)" in note
    rejected = [e for e in _events(capsys) if e["event"] == obs.ROWS_REJECTED]
    assert rejected and rejected[0]["alertable"] is True


def test_past_the_reject_limit_the_run_fails(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_INGEST_MAX_REJECTS", "1")
    with pytest.raises(RuntimeError, match="SECOPS_INGEST_MAX_REJECTS"):
        run_mod.execute(_Source([T1, None, None, T2]), deadline_sec=3600)
    assert harness["finished"][-1][0] == "FAILED"
    assert harness["watermarks"] == []


def test_a_reject_limit_of_zero_restores_fail_on_first(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPS_INGEST_MAX_REJECTS", "0")
    with pytest.raises(RuntimeError):
        run_mod.execute(_Source([T1, None]), deadline_sec=3600)


# -- V-29: a run that could not be constructed ------------------------------------

def test_an_unstartable_run_leaves_a_failed_row(
    harness: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_mod.record_unstartable("wazuh", "SecretError: no map_source") is True
    assert harness["started"] == ["wazuh"]
    assert harness["finished"] == [("FAILED", 0, 0, "SecretError: no map_source")]
    (event,) = _events(capsys)
    assert (event["event"], event["stage"]) == (obs.RUN_FAILED, "provider")


def test_an_unstartable_run_with_no_warehouse_still_emits(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def refuse(provider: object = None) -> Any:
        raise RuntimeError("SECOPS_DB_DSN is not set")

    monkeypatch.setattr(run_mod.db, "connect", refuse)
    assert run_mod.record_unstartable("wazuh", "boom") is False
    assert [e["event"] for e in _events(capsys)] == [obs.RUN_FAILED]


def test_an_unstartable_disabled_source_writes_no_row(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(run_mod, "_pack_state_of", lambda conn, name: "DISABLED")
    assert run_mod.record_unstartable("wazuh", "boom") is False
    assert harness["started"] == []


# -- the note invariant the transform depends on ----------------------------------
#
# The transform copies an xdr_endpoints snapshot only when its run is
# SUCCESS AND error_summary IS NULL. So a complete run must record NULL, and
# every incomplete one -- stopped, partial, or with rejected records -- must
# record a note. An informational note on a complete run would make the
# transform skip every snapshot.

@pytest.mark.parametrize(
    ("marks", "during", "deadline", "complete"),
    [
        ([T1, T2], None, 3600, True),
        ([T1, T2], None, 0, False),                                     # deadline stop
        ([T1, T2], lambda: context.report_partial("short"), 3600, False),
        ([T1, None, T2], None, 3600, False),                            # a rejected record
        ([T1, T2], lambda: context.cap_watermark(T1), 3600, True),      # ceiling is not partial
    ],
    ids=["complete", "stopped", "partial", "rejected", "capped"],
)
def test_only_a_complete_run_records_no_note(
    harness: dict[str, Any], marks: list[Any], during: Any, deadline: int,
    complete: bool,
) -> None:
    run_mod.execute(_Source(marks, ordered=False, during=during), deadline_sec=deadline)
    status, _read, _written, note = harness["finished"][-1]
    assert status == "SUCCESS"
    assert (note is None) is complete, note
