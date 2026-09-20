"""Structured observability for secops_ingest.

Why this exists
---------------
`ingest_run` is the audit trail, and LogicMonitor reads it over JDBC. That works
until the warehouse itself is the problem: a connector that cannot reach
Postgres, or whose credentials were revoked, cannot record its own failure in a
table that lives in Postgres. LM then sees only staleness (`rows_24h == 0`),
up to 24h late and reporting the wrong cause.

This is the same reasoning phase-4b already applies to Metabase -- "an alert
engine cannot report that it is down" -- extended to the warehouse.

So every event is emitted to **stdout as one JSON object per line** (journald
picks it up, systemd catches non-zero exits) and optionally forwarded to a
**syslog collector** so the SOC sees pipeline failures in XDR alongside
everything else.

Emit points are deliberately outside the DB write path.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import sys
import time
from typing import Any

# Stable vocabulary. Alert rules key off these, so treat them as an interface:
# adding is safe, renaming is a breaking change.
RUN_START = "run.start"
RUN_OK = "run.ok"
RUN_FAILED = "run.failed"
AUTH_FAILED = "auth.failed"
RATE_LIMITED = "http.rate_limited"
RETRY = "http.retry"
RETRY_EXHAUSTED = "http.retry_exhausted"
WAREHOUSE_UNREACHABLE = "warehouse.unreachable"
WATERMARK_ADVANCED = "watermark.advanced"
SCHEMA_DRIFT = "schema.drift"
ROWS_LANDED = "rows.landed"

# Events that should page someone. Kept here so the list is reviewable in one
# place rather than scattered across call sites.
ALERTABLE = frozenset({
    RUN_FAILED, AUTH_FAILED, RETRY_EXHAUSTED, WAREHOUSE_UNREACHABLE, SCHEMA_DRIFT,
})

_SEVERITY = {
    RUN_START: "INFO", RUN_OK: "INFO", ROWS_LANDED: "INFO", WATERMARK_ADVANCED: "INFO",
    RETRY: "WARNING", RATE_LIMITED: "WARNING",
    RUN_FAILED: "ERROR", AUTH_FAILED: "ERROR", RETRY_EXHAUSTED: "ERROR",
    WAREHOUSE_UNREACHABLE: "CRITICAL", SCHEMA_DRIFT: "ERROR",
}

_SYSLOG_LEVEL = {
    "INFO": logging.INFO, "WARNING": logging.WARNING,
    "ERROR": logging.ERROR, "CRITICAL": logging.CRITICAL,
}

_HOST = socket.gethostname()
_logger: logging.Logger | None = None


def _syslog_logger() -> logging.Logger | None:
    """Lazily build a syslog logger if a collector is configured.

    SECOPS_SYSLOG_HOST / SECOPS_SYSLOG_PORT point at the collector (an XDR
    Broker VM syslog collector, or rsyslog relaying to one). Unset means
    stdout-only, which is the safe default: a missing collector must never
    stop ingestion.
    """
    global _logger
    if _logger is not None:
        return _logger
    host = os.getenv("SECOPS_SYSLOG_HOST")
    if not host:
        return None
    port = int(os.getenv("SECOPS_SYSLOG_PORT", "514"))
    proto = os.getenv("SECOPS_SYSLOG_PROTO", "udp").lower()
    sock = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    lg = logging.getLogger("secops_ingest.syslog")
    lg.setLevel(logging.INFO)
    lg.propagate = False
    if not lg.handlers:
        try:
            h = logging.handlers.SysLogHandler(
                address=(host, port), socktype=sock,
                facility=logging.handlers.SysLogHandler.LOG_LOCAL5)
            # Python appends a NUL terminator by default. Strict RFC5424
            # collectors and any JSON parser downstream choke on it.
            h.append_nul = False
            h.setFormatter(logging.Formatter("secops_ingest: %(message)s"))
            lg.addHandler(h)
        # Deliberately blind: this module's contract is that observability
        # never fails the run it is observing. A collector that is down,
        # misconfigured or unresolvable degrades to stdout-only.
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({
                "ts": _now(), "event": "obs.syslog_unavailable",
                "severity": "WARNING", "host": _HOST, "error": str(exc)[:200],
            }), file=sys.stdout, flush=True)
            return None
    _logger = lg
    return lg


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def emit(event: str, source: str, run_id: int | None = None,
         **fields: Any) -> dict[str, Any]:
    """Emit one structured event to stdout, and to syslog when configured.

    Never raises: observability failing must not fail the run.
    """
    severity = _SEVERITY.get(event, "INFO")
    rec = {
        "ts": _now(),
        "event": event,
        "severity": severity,
        "source": source,
        "host": _HOST,
        "alertable": event in ALERTABLE,
    }
    if run_id is not None:
        rec["run_id"] = run_id
    for k, v in fields.items():
        if k not in rec:
            rec[k] = v

    line = json.dumps(rec, separators=(",", ":"), default=str, sort_keys=False)
    try:
        print(line, file=sys.stdout, flush=True)
    # Nothing to log to: stdout IS the reporting channel, so a failure here has
    # no surviving way to announce itself. Swallowing is the only option that
    # keeps ingestion running, which is the whole point of this module.
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        lg = _syslog_logger()
        if lg:
            lg.log(_SYSLOG_LEVEL.get(severity, logging.INFO), line)
    # The event already reached stdout above, so a syslog failure has been
    # reported by definition. Re-raising would turn a degraded collector into a
    # failed ingest run.
    except Exception:  # noqa: BLE001, S110
        pass
    return rec
