"""Worker lifecycle.

Every connector implements the same small protocol; this module owns the parts
that must not vary: run bookkeeping, batching, idempotent landing, and the
ordering rule that the watermark advances only after a successful land.

Refines the five-function contract in the runbooks: connectors describe how to
map a record, and the framework owns landing, so upsert logic exists once
rather than once per connector.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol

from ..packs.registry import discover as _discover_packs
from ..redaction import scrub
from . import context, db, obs, schema_check
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
#:
#: Overridden per run by SECOPS_INGEST_DEADLINE_SEC, and derived from
#: SECOPS_INGEST_UNIT_CAP_SEC when only the cap is given -- see resolve_deadline.
DEFAULT_DEADLINE_SEC = 1500

#: What a run needs between its deadline and the unit's cap: one in-flight
#: request to return, the final batch to land, the ledger row to close.
DEADLINE_MARGIN_SEC = 300

#: The unit cap this package assumes when the unit does not state one: the
#: TimeoutStartSec every ingest unit ships with.
DEFAULT_UNIT_CAP_SEC = 1800

#: Records a run may reject -- skip because to_row or watermark_of raised --
#: before the run fails instead. See SECOPS_INGEST_MAX_REJECTS.
DEFAULT_MAX_REJECTS = 10


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer number of seconds, got {raw!r}") from exc


def resolve_deadline() -> int:
    """This run's deadline, kept below the unit's cap.

    The deadline and the cap used to be set in different places: the package
    defaulted to 1500s, and the deploy raised one source's TimeoutStartSec to
    3600s without touching it. That source then stopped at 1500s every hour,
    kept its cursor because it is unordered, reported SUCCESS-with-note, and
    never scanned the oldest quarter of its collection. And a cap BELOW the
    deadline is worse: systemd kills the run first and leaves a RUNNING row.

    So when the unit says what its cap is (SECOPS_INGEST_UNIT_CAP_SEC):
      * no deadline given -> the cap minus the margin, so raising the cap
        alone is enough;
      * a deadline that leaves less than the margin, or none at all -> clamped
        to the cap minus the margin, with a warning every run. Clamped rather
        than refused: refusing would take the source dark over the one setting
        that exists to keep it alive.
    """
    deadline = _env_int("SECOPS_INGEST_DEADLINE_SEC")
    cap = _env_int("SECOPS_INGEST_UNIT_CAP_SEC")
    if cap is None or cap <= 0:
        return DEFAULT_DEADLINE_SEC if deadline is None else deadline
    # A quarter of a small cap rather than the full margin, so a short test
    # unit is not left with a zero or negative deadline.
    ceiling = cap - min(DEADLINE_MARGIN_SEC, cap // 4)
    if deadline is None:
        return ceiling
    if deadline < 0 or deadline > ceiling:
        log.warning(
            "SECOPS_INGEST_DEADLINE_SEC=%s leaves less than %ss before the unit's "
            "%ss cap (SECOPS_INGEST_UNIT_CAP_SEC); using %ss so the run stops "
            "before systemd kills it. Set the deadline below the cap to silence this.",
            deadline, cap - ceiling, cap, ceiling,
        )
        return ceiling
    return deadline


def _reap_after(deadline: int) -> int | None:
    """Age past which a RUNNING row of this source cannot belong to a live run.

    The unit's cap when it is stated. Otherwise the shipped cap, or the
    deadline plus its margin if that is later; with no deadline and no cap
    there is no age a live run could not reach, so nothing is reaped.
    """
    cap = _env_int("SECOPS_INGEST_UNIT_CAP_SEC")
    if cap is not None and cap > 0:
        return cap
    if deadline < 0:
        return None
    return max(DEFAULT_UNIT_CAP_SEC, deadline + DEADLINE_MARGIN_SEC)


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
    if stored is not None:
        _warn_version_drift(owner, stored.version)
    if stored is None or stored.state != "DISABLED":
        return None
    return stored.state


def _describe_drift(stored: str, installed: str) -> str | None:
    """packs.version.describe_drift, or None where this build lacks it.

    The comparison ships with the pack-version work (V-31) on a separate
    branch. Imported lazily so this module works on either side of that merge:
    without it the worker simply does not warn, which is what it did before.
    """
    try:
        from ..packs.version import describe_drift  # type: ignore[attr-defined,unused-ignore]
    except ImportError:
        return None
    result = describe_drift(stored, installed)
    return None if result is None else str(result)


def _warn_version_drift(pack_name: str, stored_version: str) -> None:
    """Warn, once per run, when control.pack records a different version.

    An upgrade that pip resolved to nothing exits 0 and looks like success; the
    stored version is the only thing that disagrees. Warn only, and never fail
    the run over it: the run's job is ingesting, and a version mismatch is a
    deployment question for whoever reads the journal.
    """
    try:
        pack = _discover_packs().get(pack_name)
        if pack is None:
            return
        drift = _describe_drift(str(stored_version), str(pack.version))
    # Deliberately blind: advisory only, see the docstring.
    except Exception:  # noqa: BLE001
        log.debug("pack version comparison failed", exc_info=True)
        return
    if drift:
        log.warning("pack %s: %s", pack_name, drift)



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
    """Run one ingest cycle. Never returns silently on failure.

    Every way out also emits a structured event (common.obs): the ledger lives
    in the warehouse, so it cannot record the failures that matter most -- the
    warehouse being unreachable, or this process being refused by it.
    """
    deadline = resolve_deadline() if deadline_sec is None else deadline_sec
    with contextlib.ExitStack() as stack:
        try:
            conn = stack.enter_context(db.connect(provider))
        except Exception as exc:
            obs.emit(obs.WAREHOUSE_UNREACHABLE, source.name,
                     error=scrub(f"{type(exc).__name__}: {exc}"))
            raise
        return _execute(conn, source, dry_run=dry_run, batch_size=batch_size,
                        provider=provider, deadline=deadline)


def _execute(
    conn: Any,
    source: Source,
    *,
    dry_run: bool,
    batch_size: int,
    provider: object | None,
    deadline: int,
) -> Result:
    try:
        # Before anything else, including the pack-state lookup below: a
        # schema behind the package turns the first run-ledger INSERT into a
        # driver traceback, and a refused run must not leave a RUNNING row.
        schema_check.verify_control_schema(conn)
        state = _pack_state_of(conn, source.name)
    except schema_check.ControlSchemaDrift as exc:
        obs.emit(obs.SCHEMA_DRIFT, source.name, error=str(exc))
        raise
    except Exception as exc:
        obs.emit(obs.RUN_FAILED, source.name, stage="setup",
                 error=scrub(f"{type(exc).__name__}: {exc}"))
        raise
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

    if not dry_run:
        _reap(conn, source.name, deadline)
    try:
        run_id = (
            0 if dry_run
            else db.start_run(conn, source.name, posture=current_posture(provider))
        )
    except Exception as exc:
        obs.emit(obs.RUN_FAILED, source.name, stage="start_run",
                 error=scrub(f"{type(exc).__name__}: {exc}"))
        raise
    obs.emit(obs.RUN_START, source.name, run_id or None, dry_run=dry_run,
             deadline_sec=deadline)
    read = written = rejected = 0
    reject_kinds: dict[str, int] = {}
    high_watermark: Any = None
    stop: str | None = None
    budget = _Budget(deadline)
    stopper = _install_sigterm()
    ctx = context.RunContext(source=source.name, run_id=run_id or None,
                             should_stop=lambda: _stop_reason(budget, stopper))
    max_rejects = _env_int("SECOPS_INGEST_MAX_REJECTS")
    if max_rejects is None:
        max_rejects = DEFAULT_MAX_REJECTS
    try:
        with context.running(ctx):
            creds = source.authenticate()
            cursor = db.get_watermark(conn, source.name)
            log.info("source=%s run=%s cursor=%s dry_run=%s",
                     source.name, run_id, cursor, dry_run)

            batch: list[tuple[Any, ...]] = []
            try:
                for record in source.fetch(creds, cursor):
                    read += 1
                    # One malformed record -- vendor schema drift on a single
                    # alert type -- used to fail the whole run, every run, so
                    # the source went dark until a code change shipped. It is
                    # now skipped, counted, and named in the run's note and in
                    # an alertable event; the run fails only past the limit,
                    # where "a bad record" has become "a changed schema".
                    try:
                        mark = source.watermark_of(record)
                        row = source.to_row(record, run_id)
                    except Exception as exc:  # noqa: BLE001 - counted, see above
                        rejected += 1
                        kind = type(exc).__name__
                        reject_kinds[kind] = reject_kinds.get(kind, 0) + 1
                        log.error("source=%s record %d rejected (%s: %s)",
                                  source.name, read, kind, scrub(str(exc))[:200])
                        if rejected > max_rejects:
                            raise RuntimeError(
                                f"{rejected} records rejected, more than the "
                                f"{max_rejects} allowed (SECOPS_INGEST_MAX_REJECTS); "
                                f"last: {kind}: {exc}"
                            ) from exc
                        continue
                    if _newer(mark, high_watermark):
                        high_watermark = mark
                    batch.append(row)
                    if len(batch) >= batch_size:
                        written += _land(conn, source, batch, dry_run)
                        batch = []
                    # Checked AFTER landing, so a stop never strands a full
                    # batch. Inside fetch() the same check runs before every
                    # request and every second of backoff (with_retries), so a
                    # stop does not wait out a retry loop either.
                    stop = _stop_reason(budget, stopper)
                    if stop:
                        break
            except context.StopRequested as exc:
                stop = exc.reason
            if batch:
                written += _land(conn, source, batch, dry_run)

        if dry_run:
            log.info("DRY RUN: would write %s row(s); nothing was written", written)
            return Result("SUCCESS", read, 0)

        # A source that read less than it was asked to says so (KSAT's short
        # walk, a page boundary that may have skipped a row). That is an early
        # stop in everything but name, and is treated as one below.
        partial = "; ".join(ctx.partial) or None

        # Ordering is deliberate: advance only after a successful land. A
        # crash before this re-fetches an overlap, which the upsert absorbs.
        #
        # A run stopped early may advance ONLY if its source declares that
        # it yields in watermark order. Otherwise "the highest mark seen"
        # says nothing about what was read, and writing it would skip every
        # record the run never reached.
        ordered = bool(getattr(source, "fetch_order_is_watermark_order", False))
        may_advance = (stop is None and partial is None) or ordered
        if (high_watermark is not None and ctx.watermark_ceiling is not None
                and _newer(high_watermark, ctx.watermark_ceiling)):
            # The source knows something the maximum does not: records below
            # the mark may have changed after the scan passed them. See
            # context.cap_watermark.
            log.info("source=%s highest mark %s capped at %s, the source's safe ceiling",
                     source.name, high_watermark, ctx.watermark_ceiling)
            high_watermark = ctx.watermark_ceiling
        if high_watermark is not None and may_advance:
            db.set_watermark(conn, source.name, high_watermark)
            obs.emit(obs.WATERMARK_ADVANCED, source.name, run_id or None,
                     watermark=str(high_watermark))
        elif high_watermark is not None:
            log.warning(
                "source=%s stopped early (%s) and does not yield in watermark "
                "order; cursor left at %s so nothing below the highest mark "
                "seen is skipped", source.name, stop or partial, cursor,
            )

        # A partial run reports SUCCESS -- it did what it could and the next
        # run continues -- but says so, because a partial run that looks
        # identical to a complete one hides the thing an operator needs.
        cursor_word = "advanced" if may_advance and high_watermark else "kept"
        notes: list[str] = []
        if stop:
            notes.append(f"stopped at {stop}: read {read} row(s), {cursor_word} the cursor")
        if partial:
            notes.append(f"incomplete: {partial}; {cursor_word} the cursor")
        if rejected:
            kinds = ", ".join(f"{k} x{n}" for k, n in sorted(reject_kinds.items()))
            notes.append(f"rejected {rejected} malformed record(s) ({kinds}); "
                         "they were skipped and are not in the warehouse")
            obs.emit(obs.ROWS_REJECTED, source.name, run_id or None, rejected=rejected,
                     kinds=kinds)
        note = "; ".join(notes) or None
        if note:
            log.warning("source=%s %s", source.name, note)
        db.finish_run(conn, run_id, "SUCCESS", read, written, note)
        obs.emit(obs.RUN_OK, source.name, run_id or None, rows_read=read,
                 rows_written=written, rows_rejected=rejected, note=note)
        return Result("SUCCESS", read, written)

    except Exception as exc:
        # Fail loudly and leave evidence. A worker that exits quietly is
        # indistinguishable from a quiet week.
        log.exception("source=%s run=%s failed", source.name, run_id)
        summary = scrub(f"{type(exc).__name__}: {exc}")
        obs.emit(obs.RUN_FAILED, source.name, run_id or None, stage="run",
                 error=summary[:2000], rows_read=read, rows_written=written)
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
                db.finish_run(conn, run_id, "FAILED", read, written, summary)
            except Exception:
                # Bookkeeping must never mask the original error.
                log.exception("could not record FAILED for run=%s", run_id)
        raise


def _reap(conn: Any, source_name: str, deadline: int) -> None:
    """Close this source's abandoned RUNNING rows; never fail the run over it."""
    age = _reap_after(deadline)
    if age is None:
        return
    try:
        closed = db.reap_abandoned(conn, source_name, age)
    # Deliberately blind: reaping tidies up after an EARLIER run. A role that
    # cannot UPDATE, or a driver hiccup, must not stop this run from working.
    except Exception as exc:  # noqa: BLE001
        log.warning("source=%s could not close abandoned RUNNING rows (%s); continuing",
                    source_name, type(exc).__name__)
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            log.debug("rollback after a failed reap also failed", exc_info=True)
        return
    if closed:
        log.warning("source=%s marked %d abandoned RUNNING row(s) older than %ss as FAILED",
                    source_name, closed, age)


def record_unstartable(source_name: str, reason: str) -> bool:
    """Leave evidence of a run that could not even be constructed.

    The secret provider is built before execute(), so a provider that fails to
    build used to exit 1 before start_run: no ledger row, and pipeline health
    showed only staleness. This records the failure as a FAILED row when the
    warehouse can be reached, and always as a `run.failed` event.

    Connects on the static DSN only, with no provider -- which is all there is
    when the provider is what failed. That is the credential the unit was
    deployed with, used here only to write the ledger, never to run the job;
    when the DB credential itself comes from the provider (SECOPS_DB_LEASE),
    resolve_conninfo refuses and the event is the only record. Never raises.
    Returns whether a row was written.
    """
    summary = scrub(reason)[:2000]
    obs.emit(obs.RUN_FAILED, source_name, stage="provider", error=summary)
    try:
        with db.connect(None) as conn:
            schema_check.verify_control_schema(conn)
            if _pack_state_of(conn, source_name) is not None:
                # DISABLED or AMBIGUOUS: execute() would not have started a
                # run either, so a FAILED row would be noise.
                return False
            run_id = db.start_run(conn, source_name)
            db.finish_run(conn, run_id, "FAILED", 0, 0, summary)
        return True
    # Deliberately blind: this runs on the way out of a failure that is already
    # being reported; failing to record it must not replace it.
    except Exception as exc:  # noqa: BLE001
        log.warning("could not record the failure in control.ingest_run (%s); "
                    "the run.failed event is the only record", type(exc).__name__)
        return False


def _land(conn: Any, source: Source, batch: list[tuple[Any, ...]], dry_run: bool) -> int:
    if dry_run:
        return len(batch)
    return db.upsert_many(conn, source.table, batch)
