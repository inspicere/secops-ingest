"""The per-target advisory lock: one writer per target at a time.

Two things must never overlap on one target, and the warehouse is the only
place both can see:

  * two transform runs -- a timer and a hand-run `python -m`, say -- each
    advancing the same watermark from a different high-water mark;
  * a transform run and `packs drop`, which deletes the target's bookkeeping
    and then drops its tables. A run in between those two steps re-creates a
    watermark and coverage for a table about to vanish, and coverage is what
    arms raw expiry.

So both take this lock, keyed on the target's name. Session-level, not
transaction-level, because the runner commits once per chunk and the lock has
to span the whole run; closing the connection releases it, so a killed process
cannot leave it held.

Driver-free on purpose: it only issues SQL through the connection it is given,
so `packs/__main__.py` can import it without importing the runner.
"""

from __future__ import annotations

from typing import Any

#: First half of the two-key advisory lock. A fixed namespace keeps these locks
#: from colliding with any other advisory lock on the warehouse that happens to
#: hash a target name the same way.
LOCK_NAMESPACE = "secops_ingest.transform"

_TRY = "SELECT pg_try_advisory_lock(hashtext(%s), hashtext(%s))"
_RELEASE = "SELECT pg_advisory_unlock(hashtext(%s), hashtext(%s))"


def try_lock_target(conn: Any, target: str) -> bool:
    """Take the target's lock without waiting. False means someone holds it.

    Never blocks: a transform that queued behind `drop` would run the moment
    the tables were gone, and one that queued behind another transform would
    only repeat its work.
    """
    with conn.cursor() as cur:
        cur.execute(_TRY, (LOCK_NAMESPACE, target))
        row = cur.fetchone()
    # Committed at once so the lock request does not hold a transaction open;
    # the lock itself is session-level and survives the commit.
    conn.commit()
    return bool(row and row[0])


def unlock_target(conn: Any, target: str) -> None:
    """Release a lock taken by try_lock_target on this same connection."""
    with conn.cursor() as cur:
        cur.execute(_RELEASE, (LOCK_NAMESPACE, target))
    conn.commit()
