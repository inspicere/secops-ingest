"""Transform target definitions.

Declarative by design: the SQL lives here, the mechanics live in runner.py.
"""

from __future__ import annotations

from .base import Target

#: Reference target matching the example connector. Mirrors the shape a real
#: target takes: narrow typed columns, retained for the full reporting period,
#: derived from a raw buffer that is dropped on schedule.
EXAMPLE = Target(
    name="example_messages",
    raw_table="raw_phisher.messages",
    fact_table="mart_fact_example_messages",
    fact_date_expr="reported_at",
    upsert_sql="""
        INSERT INTO mart_fact_example_messages
            (message_id, reported_at, updated_at, status, category, severity)
        SELECT
            source_id,
            (payload->>'createdAt')::timestamptz,
            (payload->>'updatedAt')::timestamptz,
            payload->>'status',
            payload->>'category',
            payload->>'severity'
        FROM raw_phisher.messages
        -- Casts are required: PostgreSQL cannot infer a type for a bare
        -- parameter used in `IS NULL`, and raises AmbiguousParameter.
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Partitioned on reported_at, so the partition key is in the primary
        -- key and therefore in the conflict target.
        ON CONFLICT (message_id, reported_at) DO UPDATE SET
            updated_at = EXCLUDED.updated_at,
            status     = EXCLUDED.status,
            category   = EXCLUDED.category,
            severity   = EXCLUDED.severity
    """,
    rollup_table="mart_rollup_example_daily",
    # Recomputes whole days from FACTS - never from raw, so the rollup stays
    # rebuildable after raw has been dropped.
    rollup_sql="""
        INSERT INTO mart_rollup_example_daily (day, status, category, severity, message_count)
        SELECT reported_at::date, status, category, severity, count(*)
        FROM mart_fact_example_messages
        WHERE reported_at::date = ANY(%(days)s)
        GROUP BY 1, 2, 3, 4
    """,
)

#: Avanan exceeds 20,000 events/day, so a 7-year trend over per-record facts
#: scans ~51M rows. The rollup reduces that to ~1.2M — 42x less — which is what
#: makes a long-horizon dashboard usable on a shared 4-core host.
#:
#: Per-record facts are retained for the full period regardless (~24GB), so this
#: grain is a performance optimisation and can be rebuilt, not a one-way door.
#:
#: EVERY DIMENSION HERE MUST BE LOW-CARDINALITY. Adding sender_domain (~5,000
#: distinct) would yield up to 120,000 rows/day — a rollup larger than the fact
#: table it summarises. High-cardinality attributes stay in the facts.
AVANAN = Target(
    name="avanan_events",
    raw_table="raw_avanan.events",
    fact_table="mart_fact_avanan_events",
    fact_date_expr="occurred_at",
    upsert_sql="""
        INSERT INTO mart_fact_avanan_events
            (event_id, occurred_at, event_type, severity, verdict, direction,
             sender_domain, subject_key)
        SELECT
            source_id,
            (payload->>'eventCreated')::timestamptz,
            payload->>'type',
            payload->>'severity',
            payload->>'state',
            payload->>'direction',
            payload->>'senderDomain',
            payload->>'subject_key'
        FROM raw_avanan.events
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        ON CONFLICT (event_id, occurred_at) DO UPDATE SET
            event_type = EXCLUDED.event_type,
            severity   = EXCLUDED.severity,
            verdict    = EXCLUDED.verdict,
            direction  = EXCLUDED.direction
    """,
    rollup_table="mart_rollup_avanan_daily",
    rollup_sql="""
        INSERT INTO mart_rollup_avanan_daily
            (day, event_type, severity, verdict, direction, event_count)
        SELECT occurred_at::date, event_type, severity, verdict, direction, count(*)
        FROM mart_fact_avanan_events
        WHERE occurred_at::date = ANY(%(days)s)
        GROUP BY 1, 2, 3, 4, 5
    """,
)

TARGETS = {t.name: t for t in (EXAMPLE, AVANAN)}
