"""Transform execution.

Ordering is deliberate throughout:

  facts -> rollups -> coverage -> watermark

Coverage is recorded only after facts exist, and the watermark advances only
after coverage is recorded. A crash anywhere re-processes an overlap, which the
idempotent upsert absorbs, rather than marking a period covered that is not.

A backlog is applied in chunks of `_ingested_at`, and that ordering holds per
chunk: each one is committed and the watermark advanced to its top before the
next begins. The role's statement_timeout then bounds a chunk, not the backlog,
and a run stopped part-way keeps every chunk it finished.

A run ends when its time is up or systemd asks it to, for the same reason as
common/run.py: a process killed at TimeoutStartSec writes no outcome and leaves
a RUNNING row forever. Here that wind-down is recorded as FAILED, with how far
it got, because a transform that has not caught up has not done its job --
unlike an ingest run, which did everything the vendor gave it in the time.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from psycopg import sql

from ..common import db, schema_check
from ..common.posture import current_posture
from ..common.schema_check import verify_control_schema
from ..packs.registry import discover as _discover_packs
from .base import Target, effective_since, should_skip
from .locks import try_lock_target, unlock_target

log = logging.getLogger(__name__)

#: Seconds a run may spend before it stops starting chunks; negative means no
#: deadline. Below the unit's 1800s TimeoutStartSec, as in common/run.py, so
#: the run stops before systemd does and leaves 300s to finish the chunk in
#: hand and close the ledger row.
DEFAULT_DEADLINE_SEC = int(os.environ.get("SECOPS_TRANSFORM_DEADLINE_SEC", "1500"))

#: Raw rows per chunk. Sized to finish in seconds, far inside the role's 900s
#: statement_timeout and inside systemd's stop timeout, so that neither can
#: cancel the same statement on every run. The first wazuh run was 1.19M rows:
#: one statement then, 24 now.
DEFAULT_CHUNK_ROWS = int(os.environ.get("SECOPS_TRANSFORM_CHUNK_ROWS", "50000"))

#: A RUNNING row older than this is a run that was killed before it could
#: write an outcome, and is closed as FAILED by the next run of its target.
#: Twice the unit's cap, so it can only ever match a process systemd has
#: already killed -- even one from a release that takes no target lock.
#: Negative disables the reaper.
#:
#: The same age decides when a RUNNING *ingest* run stops holding back a
#: complete_runs_only target: younger, it may still finish and its rows wait;
#: older, it is dead and its rows are skipped as an incomplete snapshot.
REAP_AFTER_SEC = int(os.environ.get("SECOPS_TRANSFORM_REAP_AFTER_SEC", "3600"))


@dataclass
class TransformResult:
    status: str
    rows_upserted: int = 0
    days_touched: int = 0
    error: str | None = None
    #: Why a run did less than a full catch-up, in the words written to the
    #: ledger's error_summary. None for an ordinary complete run.
    note: str | None = None


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
    """SIGTERM handler: set a flag, and cancel the chunk in flight.

    The flag alone is what common/run.py does, and it is not enough here. A
    chunk is a single server-side statement, and Python does not get to look
    at a flag until it returns; systemd sends SIGKILL after TimeoutStopSec
    (90s by default) regardless. Cancelling the statement turns the stop into
    an immediate QueryCanceled, which the runner rolls back and records.

    Only while a chunk is in flight (`armed`): cancelling at any other moment
    could cancel the ledger write that records the stop.
    """

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.signalled = False
        self.armed = False
        self.previous: Any = None
        self.installed = False

    def __call__(self, signum: int, frame: Any) -> None:
        self.signalled = True
        if not self.armed:
            return
        try:
            self.conn.cancel_safe()
        # A failed cancel leaves the flag set, which still stops the run at
        # the next chunk boundary; raising out of a signal handler would
        # instead surface at an arbitrary line.
        except Exception:  # noqa: BLE001
            log.warning("SIGTERM: could not cancel the statement in flight")

    def install(self) -> None:
        """Take SIGTERM, falling back silently off the main thread.

        signal.signal raises ValueError outside the main thread, which is where
        tests and embedders may call this; losing the handler there is
        harmless because nothing is sending the process a signal.
        """
        try:
            self.previous = signal.signal(signal.SIGTERM, self)
            self.installed = True
        except ValueError:  # pragma: no cover - not the main thread
            log.debug("not the main thread; SIGTERM handler not installed")

    def restore(self) -> None:
        if self.installed:
            signal.signal(signal.SIGTERM, self.previous)
            self.installed = False


def _stop_reason(budget: _Budget, stopper: _Stopper) -> str | None:
    if stopper.signalled:
        return "SIGTERM"
    if budget.expired():
        return f"the {budget.seconds}s deadline"
    return None


def _verify_target_schema(conn: Any, target: Target) -> None:
    """Refuse to run against target tables older than this package.

    MERGE WINDOW: verify_target_schema lands on fix/audit-schema, not on this
    branch, so it is looked up rather than imported; on a tree without it this
    is the old behaviour. Once both branches are merged, replace this with a
    direct call to schema_check.verify_target_schema(conn, [target]).
    """
    check = getattr(schema_check, "verify_target_schema", None)
    if check is None:
        log.debug("schema_check has no verify_target_schema; target drift check skipped")
        return
    check(conn, [target])


def _start(conn: Any, target: str, posture: str | None) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.transform_run (target, status, posture) "
            "VALUES (%s, 'RUNNING', %s) RETURNING run_id",
            (target, posture),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return int(run_id)


def _finish(
    conn: Any, run_id: int, status: str, rows: int, days: int, error: str | None
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            # clock_timestamp(), not now(): now() is the TRANSACTION start time,
            # and a transform that writes nothing leaves the transaction opened
            # at its first read still current here -- so the run would be
            # recorded as having taken no time. Same defect as
            # common.db.finish_run, which has the full explanation.
            "UPDATE control.transform_run SET ended_at = clock_timestamp(), status = %s, "
            "rows_upserted = %s, days_touched = %s, error_summary = %s WHERE run_id = %s",
            (status, rows, days, (error or "")[:2000] or None, run_id),
        )
    conn.commit()


def _reap_abandoned(conn: Any, target: str, older_than_sec: int) -> list[int]:
    """Close this target's RUNNING rows that no live process can own.

    A run killed by SIGKILL -- a unit timeout, the OOM killer, a host reboot --
    never reaches its except clause, so its row says RUNNING forever. Anything
    that counts FAILED runs never sees it, and the last-run view shows a
    transform perpetually in progress. Called while holding the target's lock,
    so no other run of this release is live; the age test covers runs from a
    release that took no lock.
    """
    if older_than_sec < 0:
        return []
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE control.transform_run SET status = 'FAILED', "
            "ended_at = clock_timestamp(), error_summary = %(why)s "
            "WHERE target = %(target)s AND status = 'RUNNING' "
            "AND started_at < clock_timestamp() - make_interval(secs => %(age)s) "
            "RETURNING run_id",
            {
                "target": target,
                "age": older_than_sec,
                "why": (
                    f"abandoned: still RUNNING after {older_than_sec}s with no "
                    "outcome recorded. The process was killed before it could "
                    "write one (unit timeout, OOM, reboot); closed by a later "
                    "run of the same target."
                ),
            },
        )
        reaped = sorted(int(r[0]) for r in cur.fetchall())
    conn.commit()
    if reaped:
        log.warning(
            "target=%s closed %d abandoned RUNNING run(s) as FAILED: %s",
            target, len(reaped), reaped,
        )
    return reaped


def _owning_packs(target_name: str) -> list[str]:
    """Names of every registered pack that declares `target_name`, sorted.

    Ordinarily exactly one: registry.all_targets refuses two packs declaring
    the same target name, and that is how every entry point gets its Target.
    """
    return sorted(
        pack.name
        for pack in _discover_packs().values()
        if any(t.name == target_name for t in pack.targets)
    )


def _disabled_owner(conn: Any, target_name: str) -> str | None:
    """The owning pack, if it is stored as DISABLED; otherwise None.

    Same rules as common.run._pack_state_of: no owning pack, no control.pack
    table, or no stored row all mean PROCEED, so a warehouse from before pack
    state is not broken by this. If more than one pack somehow declares the
    target, any one of them being DISABLED refuses the run: failing closed
    costs one cycle, guessing wrong runs a pack the operator turned off.
    """
    owners = _owning_packs(target_name)
    if not owners:
        return None

    from ..packs import state as pack_state  # lazy: needs the 'postgres' extra

    for owner in owners:
        stored = pack_state.get_state(conn, owner)
        if stored is not None and stored.state == "DISABLED":
            return owner
    return None


def _watermark(conn: Any, target: str) -> Any:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cursor_value FROM control.transform_watermark WHERE target = %s",
            (target,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def _advance(conn: Any, target: str, value: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO control.transform_watermark (target, cursor_value, updated_at) "
            "VALUES (%s, %s, now()) ON CONFLICT (target) DO UPDATE "
            "SET cursor_value = EXCLUDED.cursor_value, updated_at = now()",
            (target, value),
        )
    conn.commit()


def _raw_mark(conn: Any, target: Target) -> tuple[Any, timedelta | None]:
    """max(_ingested_at) of the raw table, and how long ago that was."""
    stmt = sql.SQL(
        "SELECT max(_ingested_at), clock_timestamp() - max(_ingested_at) FROM {}"
    ).format(sql.Identifier(*target.raw_table.split(".")))
    with conn.cursor() as cur:
        cur.execute(stmt)
        row = cur.fetchone()
    if row is None:
        raise RuntimeError(
            f"target={target.name}: SELECT max(_ingested_at) produced no row"
        )
    return row[0], row[1]


def _idle_note(target: Target, since: Any, new_mark: Any, age: timedelta | None) -> str:
    """Why a run moved nothing, in words a freshness check can show.

    A plain SUCCESS with 0 rows reads the same whether raw is current and
    quiet or the source stopped landing a week ago. The second is the one an
    operator needs to see, and the transform is the only stage that knows the
    mart is frozen because raw is.
    """
    if new_mark is None:
        return f"nothing to do: {target.raw_table} is empty"
    ago = str(age - timedelta(microseconds=age.microseconds)) if age is not None else "?"
    return (
        f"nothing new: {target.raw_table} last received rows at "
        f"{new_mark.isoformat()} ({ago} ago), not after the watermark {since}. "
        "The mart is as fresh as raw; if that age is longer than the source's "
        "schedule, the source is what has stopped."
    )


def _hold_for_running_ingest(
    conn: Any, target: Target, since: Any, new_mark: Any, max_age_sec: int
) -> tuple[Any, str | None]:
    """Cap the mark below any ingest run still in progress.

    A complete_runs_only upsert skips rows whose run is not yet SUCCESS. Rows
    of a run that is merely still RUNNING would be skipped too, and once the
    watermark passed them they would never be looked at again -- the snapshot
    would be lost when it completed. So the mark stops just below the first
    row of any live run, and the next transform after it finishes copies it.
    """
    raw = sql.Identifier(*target.raw_table.split("."))
    stmt = sql.SQL(
        "SELECT min(r._ingested_at), array_agg(DISTINCT i.run_id ORDER BY i.run_id) "
        "FROM {raw} r JOIN control.ingest_run i ON i.run_id = r._source_run_id "
        "WHERE i.status = 'RUNNING' "
        "  AND (%(age)s < 0 OR i.started_at > "
        "       clock_timestamp() - make_interval(secs => %(age)s)) "
        "  AND (%(since)s::timestamptz IS NULL OR r._ingested_at > %(since)s::timestamptz) "
        "  AND r._ingested_at <= %(mark)s::timestamptz"
    ).format(raw=raw)
    with conn.cursor() as cur:
        cur.execute(stmt, {"age": max_age_sec, "since": since, "mark": new_mark})
        row = cur.fetchone()
        if row is None or row[0] is None:
            return new_mark, None
        first_live, run_ids = row
        cur.execute(
            sql.SQL("SELECT max(_ingested_at) FROM {raw} WHERE _ingested_at < %s").format(
                raw=raw
            ),
            (first_live,),
        )
        below = cur.fetchone()
    held = below[0] if below else None
    note = (
        f"held back below ingest run(s) {list(run_ids)} still RUNNING: their "
        "rows are copied by the first transform after the run completes"
    )
    return held, note


def _skipped_runs_note(conn: Any, target: Target, since: Any, until: Any) -> str | None:
    """Which ingest runs in (since, until] the upsert left out, and why.

    Without this a skipped snapshot is silent: the mart simply has no rows for
    that day, which is indistinguishable from the snapshot never being taken.
    """
    stmt = sql.SQL(
        "SELECT r._source_run_id, i.status, i.error_summary IS NOT NULL, count(*) "
        "FROM {raw} r LEFT JOIN control.ingest_run i ON i.run_id = r._source_run_id "
        "WHERE (%(since)s::timestamptz IS NULL OR r._ingested_at > %(since)s::timestamptz) "
        "  AND r._ingested_at <= %(until)s::timestamptz "
        "  AND NOT COALESCE(i.status = 'SUCCESS' AND i.error_summary IS NULL, false) "
        "GROUP BY 1, 2, 3 ORDER BY 1"
    ).format(raw=sql.Identifier(*target.raw_table.split(".")))
    with conn.cursor() as cur:
        cur.execute(stmt, {"since": since, "until": until})
        rows = cur.fetchall()
    if not rows:
        return None
    parts = []
    for run_id, status, noted, n in rows:
        if status is None:
            why = "no ingest_run row"
        elif status == "SUCCESS" and noted:
            why = "SUCCESS with a note (incomplete)"
        elif status == "RUNNING":
            why = "RUNNING, abandoned"
        else:
            why = str(status)
        parts.append(f"run {run_id} {why}: {n} row(s)")
    total = sum(int(r[3]) for r in rows)
    return (
        f"skipped {total} raw row(s) from incomplete ingest run(s), so their "
        f"snapshot(s) were not copied: {'; '.join(parts)}"
    )


def _next_bound(conn: Any, target: Target, lo: Any, hi: Any, chunk_rows: int) -> Any:
    """The `_ingested_at` that closes a chunk of about `chunk_rows` raw rows.

    The chunk is (lo, bound]. Every row sharing the bound's timestamp falls in
    this chunk, so a chunk can run over by the rows of one ingest commit, which
    lands at most one batch per timestamp. `hi` when fewer rows remain.
    """
    stmt = sql.SQL(
        "SELECT _ingested_at FROM {raw} "
        "WHERE (%(lo)s::timestamptz IS NULL OR _ingested_at > %(lo)s::timestamptz) "
        "  AND _ingested_at <= %(hi)s::timestamptz "
        "ORDER BY _ingested_at OFFSET %(skip)s LIMIT 1"
    ).format(raw=sql.Identifier(*target.raw_table.split(".")))
    with conn.cursor() as cur:
        cur.execute(stmt, {"lo": lo, "hi": hi, "skip": max(chunk_rows - 1, 0)})
        row = cur.fetchone()
    return row[0] if row else hi


def _chunks(
    conn: Any, target: Target, lo: Any, hi: Any, chunk_rows: int
) -> Iterator[tuple[Any, Any]]:
    """(since, until) pairs covering (lo, hi], computed lazily.

    Lazily, so a run stopped after three chunks has not first walked the index
    for all twenty-four.
    """
    while True:
        bound = _next_bound(conn, target, lo, hi, chunk_rows)
        yield lo, bound
        if bound >= hi:
            return
        lo = bound


def _apply_chunk(
    conn: Any, target: Target, since: Any, until: Any
) -> tuple[int, list[date]]:
    """facts -> rollups -> coverage for one slice. The caller commits."""
    with conn.cursor() as cur:
        cur.execute(target.upsert_sql, {"since": since, "until": until})
        rows = cur.rowcount
    days = _affected_days(conn, target, since, until)
    if target.rollup_sql and days:
        _rebuild_rollups(conn, target, days)
    _record_coverage(conn, target, days)
    return rows, days


def execute(
    target: Target,
    *,
    deadline_sec: int | None = None,
    chunk_rows: int | None = None,
) -> TransformResult:
    budget = _Budget(DEFAULT_DEADLINE_SEC if deadline_sec is None else deadline_sec)
    chunk_rows = DEFAULT_CHUNK_ROWS if chunk_rows is None else chunk_rows
    with db.connect() as conn:
        # Before the run-ledger INSERT below: a schema behind the package
        # turns it into a driver traceback, and a refused run must not leave
        # a RUNNING row behind.
        verify_control_schema(conn)
        # Same placement and reason for the target's own raw, fact and rollup
        # tables: a column the package writes but the warehouse lacks used to
        # surface as an UndefinedColumn traceback on every run (V-32).
        _verify_target_schema(conn, target)

        # Before anything that writes. Held for the whole run; `packs drop`
        # takes the same lock, so it cannot delete this target's bookkeeping
        # while a run is re-creating it.
        if not try_lock_target(conn, target.name):
            # Not a failure: the timer fired while a hand-run (or a drop) was
            # in progress, and the next tick picks up where that one ends.
            log.warning(
                "target=%s is locked by another transform run or a `packs drop`; "
                "not running (writes nothing)", target.name,
            )
            return TransformResult("BUSY")
        try:
            owner = _disabled_owner(conn, target.name)
            if owner is not None:
                # Before _start, for the reason common/run.py gives: a
                # disabled pack leaves no RUNNING row, and exits 0 because the
                # operator disabled it on purpose.
                log.warning(
                    "pack=%s target=%s is disabled; refusing to run (writes nothing)",
                    owner, target.name,
                )
                return TransformResult("DISABLED")

            _reap_abandoned(conn, target.name, REAP_AFTER_SEC)

            stopper = _Stopper(conn)
            stopper.install()
            try:
                return _run(conn, target, budget, stopper, chunk_rows)
            finally:
                stopper.restore()
        finally:
            try:
                # Rolled back first: after a failure the connection may be in
                # an aborted transaction, which would refuse the unlock.
                conn.rollback()
                unlock_target(conn, target.name)
            # Closing the connection releases the lock anyway; an unlock that
            # fails must not replace whatever this run is returning or raising.
            except Exception:  # noqa: BLE001
                log.warning("target=%s: could not release the target lock", target.name)


def _run(
    conn: Any, target: Target, budget: _Budget, stopper: _Stopper, chunk_rows: int
) -> TransformResult:
    # No secret provider reaches the transform runner yet, so this records
    # None until a provider is threaded through.
    run_id = _start(conn, target.name, current_posture(None))
    rows = 0
    days: set[date] = set()
    chunks_done = 0
    try:
        since = _watermark(conn, target.name)

        # High-water mark captured BEFORE the upsert. Rows arriving mid-run
        # are simply picked up next time; advancing to a mark taken after
        # would skip them.
        new_mark, age = _raw_mark(conn, target)
        notes: list[str] = []
        if target.complete_runs_only and new_mark is not None:
            new_mark, held = _hold_for_running_ingest(
                conn, target, effective_since(target, since), new_mark, REAP_AFTER_SEC
            )
            if held:
                log.info("target=%s %s", target.name, held)
                notes.append(held)

        if should_skip(target, since, new_mark) or new_mark is None:
            idle = "; ".join([_idle_note(target, since, new_mark, age), *notes])
            log.info("target=%s %s", target.name, idle)
            _finish(conn, run_id, "SUCCESS", 0, 0, idle)
            return TransformResult("SUCCESS", note=idle)

        lo = effective_since(target, since)
        if target.complete_runs_only:
            # Over the whole slice this run will cover, before any chunk: a
            # run stopped part-way then still names what it would have left out.
            skipped = _skipped_runs_note(conn, target, lo, new_mark)
            if skipped:
                log.warning("target=%s %s", target.name, skipped)
                notes.append(skipped)
        if target.chunkable:
            slices: Iterator[tuple[Any, Any]] = _chunks(conn, target, lo, new_mark, chunk_rows)
        else:
            # A pack target from before %(until)s: one unbounded statement,
            # as every target used to be. It still works; it is exposed to the
            # statement_timeout livelock, and the ledger says so.
            legacy = (
                f"applied as one statement: target {target.name} has no "
                "%(until)s bound, so a backlog cannot be chunked and one longer "
                "than the role's statement_timeout will fail on every run"
            )
            log.warning("target=%s %s", target.name, legacy)
            notes.append(legacy)
            slices = iter([(lo, None)])
        note = "; ".join(notes) or None

        for chunk_since, chunk_until in slices:
            stop = _stop_reason(budget, stopper)
            if stop:
                # The stop is checked BEFORE a chunk, never inside one: every
                # chunk that starts is either committed whole or rolled back.
                reached = _watermark(conn, target.name)
                why = (
                    f"stopped at {stop} after {chunks_done} chunk(s): "
                    f"{rows} row(s) upserted, watermark at {reached}, raw at "
                    f"{new_mark}. The next run continues from the watermark."
                    + (f" Also: {note}" if note else "")
                )
                log.warning("target=%s run=%s %s", target.name, run_id, why)
                _finish(conn, run_id, "FAILED", rows, len(days), why)
                return TransformResult("FAILED", rows, len(days), error=why)

            stopper.armed = True
            try:
                n, chunk_days = _apply_chunk(conn, target, chunk_since, chunk_until)
            finally:
                stopper.armed = False
            conn.commit()
            # The legacy single statement has no top of its own; the mark
            # captured before it is still the right one to advance to.
            _advance(conn, target.name, new_mark if chunk_until is None else chunk_until)
            rows += n
            days.update(chunk_days)
            chunks_done += 1
            log.info(
                "target=%s chunk=%d rows=%s up to %s",
                target.name, chunks_done, n, chunk_until or new_mark,
            )

        _finish(conn, run_id, "SUCCESS", rows, len(days), note)
        log.info("target=%s rows=%s days=%s chunks=%s",
                 target.name, rows, len(days), chunks_done)
        return TransformResult("SUCCESS", rows, len(days), note=note)

    except Exception as exc:
        log.exception("target=%s run=%s failed", target.name, run_id)
        try:
            conn.rollback()
        # Deliberately blind: this runs while another exception is
        # unwinding. A narrower clause would let a rollback failure
        # replace the original error, which is the one worth reading.
        except Exception:  # pragma: no cover - defensive  # noqa: BLE001
            log.warning("rollback failed while handling a transform failure")
        # A cancelled chunk under SIGTERM is a stop, not a crash, and the
        # ledger should say which; the chunks before it stay committed.
        prefix = "stopped at SIGTERM during a chunk; " if stopper.signalled else ""
        why = (
            f"{prefix}{type(exc).__name__}: {exc} "
            f"[after {chunks_done} committed chunk(s), {rows} row(s)]"
        )
        try:
            _finish(conn, run_id, "FAILED", rows, len(days), why)
        except Exception:
            log.exception("could not record FAILED for transform run=%s", run_id)
        raise


def _affected_days(conn: Any, target: Target, since: Any, until: Any = None) -> list[date]:
    """Days touched by THIS chunk, derived from raw rows in (since, until].

    Deliberately not a scan of the fact table: that would return every day the
    target has ever produced, so a single new record would trigger a rebuild of
    every rollup in the table. `until` None is the unbounded legacy statement.
    """
    stmt = sql.SQL(
        # Cast for the same reason as in targets.py: a bare parameter inside
        # IS NULL has no type context and PostgreSQL refuses it.
        "SELECT DISTINCT _event_time::date AS d FROM {raw} "
        "WHERE (%(since)s::timestamptz IS NULL "
        "       OR _ingested_at > %(since)s::timestamptz) "
        "  AND (%(until)s::timestamptz IS NULL "
        "       OR _ingested_at <= %(until)s::timestamptz) ORDER BY d"
    ).format(raw=sql.Identifier(*target.raw_table.split(".")))
    with conn.cursor() as cur:
        cur.execute(stmt, {"since": since, "until": until})
        return [r[0] for r in cur.fetchall()]


def _rebuild_rollups(conn: Any, target: Target, days: list[date]) -> None:
    """Recompute whole days from FACTS. Never increment.

    Incrementing double-counts on any retry. The day is cleared and rebuilt in
    one transaction so a dashboard never sees it briefly absent, and stale
    dimension combinations that no longer have rows disappear.
    """
    # Target.__post_init__ requires rollup_table and rollup_sql to be set
    # together, and the only caller guards on rollup_sql -- so rollup_table
    # is guaranteed non-None here.
    assert target.rollup_table is not None
    delete = sql.SQL("DELETE FROM {} WHERE day = ANY(%(days)s)").format(
        sql.Identifier(target.rollup_table)
    )
    with conn.cursor() as cur:
        cur.execute(delete, {"days": days})
        cur.execute(target.rollup_sql, {"days": days})


def _record_coverage(conn: Any, target: Target, days: list[date]) -> None:
    """Prove a period's reporting rows exist, so raw expiry can be gated on it."""
    if not days:
        return
    months = sorted({d.replace(day=1) for d in days})
    stmt = sql.SQL(
        "INSERT INTO control.transform_coverage (target, period, fact_rows) "
        "SELECT %(target)s, date_trunc('month', {date_expr})::date, count(*) "
        "FROM {fact} WHERE date_trunc('month', {date_expr})::date = ANY(%(months)s) "
        "GROUP BY 2 "
        "ON CONFLICT (target, period) DO UPDATE "
        "SET fact_rows = EXCLUDED.fact_rows, completed_at = now()"
    ).format(
        fact=sql.Identifier(target.fact_table),
        date_expr=sql.SQL(target.fact_date_expr),
    )
    with conn.cursor() as cur:
        cur.execute(stmt, {"target": target.name, "months": months})
