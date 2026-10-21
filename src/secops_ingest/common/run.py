"""Worker lifecycle.

Every connector implements the same small protocol; this module owns the parts
that must not vary: run bookkeeping, batching, idempotent landing, and the
ordering rule that the watermark advances only after a successful land.

Refines the five-function contract in the runbooks: connectors describe how to
map a record, and the framework owns landing, so upsert logic exists once
rather than once per connector.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol

from ..packs.registry import discover as _discover_packs
from ..redaction import scrub
from . import db, schema_check
from .posture import current_posture
from .watermark import newer as _newer

log = logging.getLogger(__name__)

#: Records are landed in batches so memory stays bounded during a backfill.
DEFAULT_BATCH = 500


class Source(Protocol):
    """What a connector must provide."""

    name: str
    table: str

    #: Does fetch() yield records in non-decreasing watermark order?
    #:
    #: Only a source that says yes may have its watermark advanced by a run that
    #: stopped early, because only then is "the highest mark seen so far" also
    #: "everything below this has been read".
    #:
    #: defectdojo scans DESCENDING -- its first page carries the highest mark --
    #: so advancing would skip every record below it. xdr_endpoints ignores the
    #: cursor entirely. Both must stay False.
    #:
    #: Absent means False. A connector written before this existed does not get
    #: its position advanced on the strength of an attribute it never set.
    fetch_order_is_watermark_order: bool

    def authenticate(self) -> Any:
        """Fetch credentials ONCE per run. Held in memory, never written."""

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict[str, Any]]:
        """Yield raw vendor records newer than `cursor`."""

    def to_row(self, record: dict[str, Any], run_id: int) -> tuple[Any, ...]:
        """Map a record to (source_id, payload, _event_time, _source_run_id).

        `_event_time` MUST come from an immutable field - the record's creation
        time, never the field the watermark uses. It is the partition key.
        """

    def watermark_of(self, record: dict[str, Any]) -> Any:
        """Value to advance the watermark to. Usually a modification time."""


#: Seconds a run may spend before it winds down, 0 meaning stop at once and a
#: negative value meaning no deadline.
#:
#: Comfortably below the unit's TimeoutStartSec, because the point is to stop
#: BEFORE systemd does: a SIGTERM kill lands rows and discards the position,
#: which is the livelock. 1500 against a 1800s cap leaves 300s to land the final
#: batch and close the ledger row.
DEFAULT_DEADLINE_SEC = int(os.environ.get("SECOPS_INGEST_DEADLINE_SEC", "1500"))


@dataclass
class Result:
    status: str
    rows_read: int = 0
    rows_written: int = 0
    error: str | None = None


def _owning_packs(source_name: str) -> list[str]:
    """Names of every registered pack that claims `source_name`, sorted.

    Ordinarily 0 or 1. More than one is the same collision
    `registry.resolve_source` refuses as `AmbiguousSource` for an
    operator-typed reference -- but `execute()` only ever has the Source
    object's own bare name to go on, not the qualified reference ("beta.shared")
    that resolved it, so it cannot tell which of the candidates is meant.
    """
    return sorted(pack.name for pack in _discover_packs().values() if source_name in pack.sources)


def _owning_pack(source_name: str) -> str | None:
    """Name of the pack that registers `source_name`, if exactly one does.

    The real fix for ambiguity is to thread the operator's qualified reference
    (e.g. "beta.shared") through into `execute()`, so this never has to guess
    at all. That changes `execute()`'s signature and the `Source` protocol's
    contract, which is out of scope for this change; `_pack_state_of`'s
    fail-closed "AMBIGUOUS" result is the stand-in guard until that lands.
    """
    owners = _owning_packs(source_name)
    return owners[0] if len(owners) == 1 else None


def _pack_state_of(conn: Any, source_name: str) -> str | None:
    """Return the disabling state of the pack that owns `source_name`.

    None covers every case in which the run must PROCEED: no pack claims this
    source (not this check's business -- something running outside a pack must
    not be broken by this), `control.pack` does not exist at all (every
    warehouse provisioned before packs had state), the pack has no stored row,
    or the row says ENABLED. Only a stored DISABLED row returns anything, so a
    caller only ever needs to compare the result to that one string.

    "AMBIGUOUS" is the fail-closed exception to that: when more than one
    registered pack claims `source_name`, there is no single pack to ask, so
    this refuses rather than guessing and risking a DISABLED pack's connector
    running because it was silently judged against an unrelated ENABLED one.
    """
    owners = _owning_packs(source_name)
    if len(owners) > 1:
        return "AMBIGUOUS"
    if not owners:
        return None
    owner = owners[0]

    from ..packs import state as pack_state  # lazy: needs the 'postgres' extra

    stored = pack_state.get_state(conn, owner)
    if stored is None or stored.state != "DISABLED":
        return None
    return stored.state



class _Budget:
    """How long this run may take. Negative means no limit."""

    def __init__(self, seconds: int) -> None:
        self.seconds = seconds
        self.started = time.monotonic()

    def expired(self) -> bool:
        if self.seconds < 0:
            return False
        return (time.monotonic() - self.started) >= self.seconds


class _Stopper:
    """Set by SIGTERM so a systemd stop becomes a wind-down."""

    def __init__(self) -> None:
        self.signalled = False

    def __call__(self, signum: int, frame: Any) -> None:
        self.signalled = True


def _install_sigterm() -> _Stopper:
    """Turn SIGTERM into a flag, falling back silently off the main thread.

    Unhandled, SIGTERM kills Python without running the except handler, so no
    terminal status is written and control.ingest_run keeps a RUNNING row
    forever. signal.signal raises ValueError outside the main thread, which is
    where tests and embedders may call this; losing the handler there is
    harmless because nothing is sending the process a signal.
    """
    stopper = _Stopper()
    try:
        signal.signal(signal.SIGTERM, stopper)
    except ValueError:  # pragma: no cover - not the main thread
        log.debug("not the main thread; SIGTERM handler not installed")
    return stopper


def _stop_reason(budget: _Budget, stopper: _Stopper) -> str | None:
    if stopper.signalled:
        return "SIGTERM"
    if budget.expired():
        return f"the {budget.seconds}s deadline"
    return None


def execute(
    source: Source,
    *,
    dry_run: bool = False,
    batch_size: int = DEFAULT_BATCH,
    provider: object | None = None,
    deadline_sec: int | None = None,
) -> Result:
    """Run one ingest cycle. Never returns silently on failure."""
    with db.connect(provider) as conn:
        # Before anything else, including the pack-state lookup below: a
        # schema behind the package turns the first run-ledger INSERT into a
        # driver traceback, and a refused run must not leave a RUNNING row.
        schema_check.verify_control_schema(conn)
        state = _pack_state_of(conn, source.name)
        if state == "AMBIGUOUS":
            # Same collision registry.resolve_source calls AmbiguousSource for,
            # and the same message voice: name the source and every candidate
            # so the operator knows exactly what to disambiguate.
            candidates = ", ".join(
                f"{pack_name}.{source.name}" for pack_name in _owning_packs(source.name)
            )
            log.error(
                "source %r is provided by more than one pack; name one of: %s",
                source.name, candidates,
            )
            return Result("AMBIGUOUS", 0, 0)
        if state == "DISABLED":
            # Deliberately before start_run: a disabled source must leave no
            # trace in control.ingest_run, not a RUNNING row that never
            # completes. The operator disabled this on purpose, so this exits
            # 0 rather than failing -- a timer that fails every interval
            # trains people to ignore alerts.
            log.warning(
                "pack=%s source=%s is disabled; refusing to run (writes nothing)",
                _owning_pack(source.name), source.name,
            )
            return Result("DISABLED", 0, 0)

        run_id = (
            0 if dry_run
            else db.start_run(conn, source.name, posture=current_posture(provider))
        )
        read = written = 0
        high_watermark: Any = None
        stop: str | None = None
        budget = _Budget(DEFAULT_DEADLINE_SEC if deadline_sec is None else deadline_sec)
        stopper = _install_sigterm()
        try:
            creds = source.authenticate()
            cursor = db.get_watermark(conn, source.name)
            log.info("source=%s run=%s cursor=%s dry_run=%s",
                     source.name, run_id, cursor, dry_run)

            batch: list[tuple[Any, ...]] = []
            for record in source.fetch(creds, cursor):
                read += 1
                mark = source.watermark_of(record)
                if _newer(mark, high_watermark):
                    high_watermark = mark
                batch.append(source.to_row(record, run_id))
                if len(batch) >= batch_size:
                    written += _land(conn, source, batch, dry_run)
                    batch = []
                # Checked AFTER landing, so a stop never strands a full batch,
                # and between records rather than inside fetch(), because the
                # connector owns its paging and this must not reach into it.
                stop = _stop_reason(budget, stopper)
                if stop:
                    break
            if batch:
                written += _land(conn, source, batch, dry_run)

            if dry_run:
                log.info("DRY RUN: would write %s row(s); nothing was written", written)
                return Result("SUCCESS", read, 0)

            # Ordering is deliberate: advance only after a successful land. A
            # crash before this re-fetches an overlap, which the upsert absorbs.
            #
            # A run stopped early may advance ONLY if its source declares that
            # it yields in watermark order. Otherwise "the highest mark seen"
            # says nothing about what was read, and writing it would skip every
            # record the run never reached.
            ordered = bool(getattr(source, "fetch_order_is_watermark_order", False))
            may_advance = stop is None or ordered
            if high_watermark is not None and may_advance:
                db.set_watermark(conn, source.name, high_watermark)
            elif high_watermark is not None:
                log.warning(
                    "source=%s stopped early (%s) and does not yield in watermark "
                    "order; cursor left at %s so nothing below the highest mark "
                    "seen is skipped", source.name, stop, cursor,
                )

            # A partial run reports SUCCESS -- it did what it could and the next
            # run continues -- but says so, because a partial run that looks
            # identical to a complete one hides the thing an operator needs.
            note = (
                f"stopped at {stop}: read {read} row(s), "
                f"{'advanced' if may_advance and high_watermark else 'kept'} the cursor"
                if stop else None
            )
            if stop:
                log.warning("source=%s %s", source.name, note)
            db.finish_run(conn, run_id, "SUCCESS", read, written, note)
            return Result("SUCCESS", read, written)

        except Exception as exc:
            # Fail loudly and leave evidence. A worker that exits quietly is
            # indistinguishable from a quiet week.
            log.exception("source=%s run=%s failed", source.name, run_id)
            if not dry_run:
                # The connection is very likely in a failed transaction: after
                # any in-transaction error PostgreSQL rejects every subsequent
                # statement with InFailedSqlTransaction (verified against
                # PostgreSQL 16). Without this rollback the bookkeeping write
                # below would itself raise, leaving the row RUNNING forever and
                # masking the real failure.
                try:
                    conn.rollback()
                # Deliberately blind: this runs while another exception is
                # unwinding. A narrower clause would let a rollback failure
                # replace the original error, which is the one worth reading.
                except Exception:  # pragma: no cover - defensive  # noqa: BLE001
                    log.warning("rollback failed while handling a run failure")
                try:
                    db.finish_run(
                        conn, run_id, "FAILED", read, written,
                        scrub(f"{type(exc).__name__}: {exc}"),
                    )
                except Exception:
                    # Bookkeeping must never mask the original error.
                    log.exception("could not record FAILED for run=%s", run_id)
            raise


def _land(conn: Any, source: Source, batch: list[tuple[Any, ...]], dry_run: bool) -> int:
    if dry_run:
        return len(batch)
    return db.upsert_many(conn, source.table, batch)
