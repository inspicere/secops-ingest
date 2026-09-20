"""Tests for secops_ingest.common.obs.

Covers the properties the alerting design depends on:
  - every event is one parseable JSON line on stdout
  - severity maps to the syslog PRI so XDR/LM can alert without parsing JSON
  - no NUL terminator (strict RFC5424 collectors and JSON parsers reject it)
  - a dead or unconfigured collector never breaks ingestion
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import socket
import threading
import time

import pytest

from secops_ingest.common import obs


def _capture(fn) -> list[dict]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


def test_emit_writes_one_json_line_per_event():
    rows = _capture(lambda: (
        obs.emit(obs.RUN_START, "xdr_incidents", run_id=1),
        obs.emit(obs.RUN_OK, "xdr_incidents", run_id=1, rows=10),
    ))
    assert len(rows) == 2
    assert [r["event"] for r in rows] == [obs.RUN_START, obs.RUN_OK]
    assert rows[1]["rows"] == 10


def test_required_fields_present():
    (row,) = _capture(lambda: obs.emit(obs.RUN_OK, "xdr_incidents", run_id=7))
    for key in ("ts", "event", "severity", "source", "host", "alertable", "run_id"):
        assert key in row, f"missing {key}"


@pytest.mark.parametrize(
    "event,severity,alertable",
    [
        (obs.RUN_OK, "INFO", False),
        (obs.RETRY, "WARNING", False),
        (obs.AUTH_FAILED, "ERROR", True),
        (obs.WAREHOUSE_UNREACHABLE, "CRITICAL", True),
        (obs.RETRY_EXHAUSTED, "ERROR", True),
    ],
)
def test_severity_and_alertable(event, severity, alertable):
    (row,) = _capture(lambda: obs.emit(event, "s"))
    assert row["severity"] == severity
    assert row["alertable"] is alertable


def test_alertable_set_matches_severity_table():
    """Anything ERROR or CRITICAL should be alertable, and vice versa."""
    for event, sev in obs._SEVERITY.items():
        if sev in ("ERROR", "CRITICAL"):
            assert event in obs.ALERTABLE, f"{event} is {sev} but not alertable"
        else:
            assert event not in obs.ALERTABLE, f"{event} is {sev} but alertable"


def test_caller_cannot_clobber_reserved_fields():
    """Extra fields must not overwrite the fields alert rules key off.

    `event`, `source` and `run_id` are named parameters, so passing them
    again is a TypeError - the interpreter enforces those. `severity`, `host`,
    `ts` and `alertable` arrive via **fields and are protected by emit().
    """
    (row,) = _capture(lambda: obs.emit(obs.AUTH_FAILED, "real_source",
                                       severity="INFO", host="spoofed",
                                       alertable=False, ts="1999-01-01T00:00:00Z"))
    assert row["severity"] == "ERROR"      # from the table, not the caller
    assert row["host"] != "spoofed"
    assert row["alertable"] is True
    assert row["ts"] != "1999-01-01T00:00:00Z"
    assert row["event"] == obs.AUTH_FAILED


@pytest.mark.parametrize("kwargs", [{"source": "spoofed"}, {"event": "run.ok"}])
def test_positional_fields_cannot_be_overridden(kwargs):
    with pytest.raises(TypeError):
        obs.emit(obs.RUN_OK, "real_source", **kwargs)


def _udp_collector():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    received: list[bytes] = []

    def listen():
        with contextlib.suppress(socket.timeout, OSError):
            while True:
                data, _ = srv.recvfrom(8192)
                received.append(data)

    threading.Thread(target=listen, daemon=True).start()
    return srv, srv.getsockname()[1], received


def test_syslog_emits_with_correct_pri_and_no_nul(monkeypatch):
    srv, port, received = _udp_collector()
    try:
        monkeypatch.setenv("SECOPS_SYSLOG_HOST", "127.0.0.1")
        monkeypatch.setenv("SECOPS_SYSLOG_PORT", str(port))
        monkeypatch.setenv("SECOPS_SYSLOG_PROTO", "udp")
        mod = importlib.reload(obs)
        with contextlib.redirect_stdout(io.StringIO()):
            mod.emit(mod.AUTH_FAILED, "xsoar_incidents", run_id=42, status=401)
        deadline = time.monotonic() + 3
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        assert received, "no syslog datagram received"
        raw = received[0]

        # A NUL terminator breaks strict RFC5424 collectors and JSON parsers.
        assert not raw.endswith(b"\x00")

        pri = int(raw[1 : raw.index(b">")])
        assert pri % 8 == 3          # err
        assert pri // 8 == 21        # local5

        payload = json.loads(raw[raw.index(b"{") :])
        assert payload["event"] == mod.AUTH_FAILED
        assert payload["alertable"] is True
    finally:
        srv.close()
        importlib.reload(obs)


def test_unreachable_collector_does_not_break_emit(monkeypatch):
    """A dead collector must degrade to stdout-only, never fail the run."""
    monkeypatch.setenv("SECOPS_SYSLOG_HOST", "203.0.113.1")  # TEST-NET-3
    monkeypatch.setenv("SECOPS_SYSLOG_PORT", "514")
    mod = importlib.reload(obs)
    try:
        rows = _capture(lambda: mod.emit(mod.RUN_OK, "xdr_incidents", run_id=1))
        assert rows and rows[0]["event"] == mod.RUN_OK
    finally:
        importlib.reload(obs)


def test_no_syslog_configured_is_stdout_only(monkeypatch):
    monkeypatch.delenv("SECOPS_SYSLOG_HOST", raising=False)
    mod = importlib.reload(obs)
    try:
        assert mod._syslog_logger() is None
        rows = _capture(lambda: mod.emit(mod.RUN_OK, "s"))
        assert len(rows) == 1
    finally:
        importlib.reload(obs)
