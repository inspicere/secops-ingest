"""What the framework knows about the run in progress, for code it cannot hand it to.

Connectors own their paging and call `with_retries` themselves, so the framework
cannot pass a stop check, a source name or a "this run is incomplete" channel
down every call path without changing every connector's signature. A context
variable carries them instead: `run.execute()` sets one for the length of a run,
and helpers deep inside `fetch()` read it.

Outside a run -- a test driving `fetch()` directly, a REPL, the transform --
there is no context, and every helper here degrades to what the code did before
it existed: never stop, report nothing, name the source "unknown".

Kept free of any driver or HTTP dependency so that both `run.py` (postgres
extra) and `http.py` (http extra) can import it on a core-only install.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class RunContext:
    """One run's identity, its stop check, and what its source said about it."""

    source: str
    run_id: int | None = None
    #: Returns why the run should stop (SIGTERM, the deadline), or None.
    should_stop: Callable[[], str | None] = lambda: None
    #: Reasons the source gave for this run being incomplete. See report_partial.
    partial: list[str] = field(default_factory=list)
    #: Highest watermark the source vouches for. See cap_watermark.
    watermark_ceiling: Any = None


class StopRequested(Exception):
    """Raised inside fetch() when the run has been asked to stop.

    An Exception rather than a BaseException so that `execute()`'s ordinary
    failure path still runs if something between here and there swallows the
    distinction -- a run that ends FAILED is recorded; one that escapes every
    handler leaves a RUNNING row.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"stop requested: {reason}")
        self.reason = reason


_current: ContextVar[RunContext | None] = ContextVar("secops_ingest_run", default=None)


def current() -> RunContext | None:
    return _current.get()


@contextmanager
def running(ctx: RunContext) -> Iterator[RunContext]:
    """Make `ctx` the current run for the length of the block."""
    token = _current.set(ctx)
    try:
        yield ctx
    finally:
        _current.reset(token)


def source_name() -> str:
    ctx = _current.get()
    return ctx.source if ctx else "unknown"


def run_id() -> int | None:
    ctx = _current.get()
    return ctx.run_id if ctx else None


def stop_reason() -> str | None:
    """Why the current run should stop, or None. Never raises.

    A broken stop check must not be what fails a run, so its own failure reads
    as "no reason to stop", the behaviour before the hook existed.
    """
    ctx = _current.get()
    if ctx is None:
        return None
    try:
        return ctx.should_stop()
    except Exception:  # noqa: BLE001 - see docstring
        log.debug("stop check raised; treating as no stop", exc_info=True)
        return None


def raise_if_stopping() -> None:
    """Raise StopRequested if the current run has been asked to stop."""
    reason = stop_reason()
    if reason:
        raise StopRequested(reason)


def report_partial(reason: str) -> None:
    """Tell the framework this run did not read everything it was asked to.

    `execute()` then treats the run as stopped early: it records `reason` in the
    run's note, and advances the watermark only if the source yields in
    watermark order -- exactly as for a deadline stop. That is the difference
    between a short read that a log line mentions and one the ledger records.

    Logged here as well, so a source driven outside a run still says so.
    """
    log.warning("%s: incomplete run: %s", source_name(), reason)
    ctx = _current.get()
    if ctx is not None:
        ctx.partial.append(reason)


def cap_watermark(value: Any) -> None:
    """Tell the framework not to persist a watermark above `value` this run.

    For a source whose scan is not a snapshot. The highest mark seen during a
    long scan is not a safe resume point if records the scan already passed
    can change while it runs: such a record gets a mark BELOW the maximum, and
    the next run filters it out as already read. A source that knows when its
    scan started can vouch only for marks up to then, and says so here.
    """
    ctx = _current.get()
    if ctx is not None:
        ctx.watermark_ceiling = value
