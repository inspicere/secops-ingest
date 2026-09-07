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
from dataclasses import dataclass
from typing import Any, Iterator, Protocol

from . import db
from .watermark import newer as _newer
from ..redaction import scrub

log = logging.getLogger(__name__)

#: Records are landed in batches so memory stays bounded during a backfill.
DEFAULT_BATCH = 500


class Source(Protocol):
    """What a connector must provide."""

    name: str
    table: str

    def authenticate(self) -> Any:
        """Fetch credentials ONCE per run. Held in memory, never written."""

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict]:
        """Yield raw vendor records newer than `cursor`."""

    def to_row(self, record: dict, run_id: int) -> tuple:
        """Map a record to (source_id, payload, _event_time, _source_run_id).

        `_event_time` MUST come from an immutable field - the record's creation
        time, never the field the watermark uses. It is the partition key.
        """

    def watermark_of(self, record: dict) -> Any:
        """Value to advance the watermark to. Usually a modification time."""


@dataclass
class Result:
    status: str
    rows_read: int = 0
    rows_written: int = 0
    error: str | None = None


def execute(source: Source, *, dry_run: bool = False, batch_size: int = DEFAULT_BATCH) -> Result:
    """Run one ingest cycle. Never returns silently on failure."""
    with db.connect() as conn:
        run_id = 0 if dry_run else db.start_run(conn, source.name)
        read = written = 0
        high_watermark: Any = None
        try:
            creds = source.authenticate()
            cursor = db.get_watermark(conn, source.name)
            log.info("source=%s run=%s cursor=%s dry_run=%s",
                     source.name, run_id, cursor, dry_run)

            batch: list[tuple] = []
            for record in source.fetch(creds, cursor):
                read += 1
                mark = source.watermark_of(record)
                if _newer(mark, high_watermark):
                    high_watermark = mark
                batch.append(source.to_row(record, run_id))
                if len(batch) >= batch_size:
                    written += _land(conn, source, batch, dry_run)
                    batch = []
            if batch:
                written += _land(conn, source, batch, dry_run)

            if dry_run:
                log.info("DRY RUN: would write %s row(s); nothing was written", written)
                return Result("SUCCESS", read, 0)

            # Ordering is deliberate: advance only after a successful land. A
            # crash before this re-fetches an overlap, which the upsert absorbs.
            if high_watermark is not None:
                db.set_watermark(conn, source.name, high_watermark)

            db.finish_run(conn, run_id, "SUCCESS", read, written)
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
                except Exception:            # pragma: no cover - defensive
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


def _land(conn, source: Source, batch: list[tuple], dry_run: bool) -> int:
    if dry_run:
        return len(batch)
    return db.upsert_many(conn, source.table, batch)
