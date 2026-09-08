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
    raw_table="raw_example.messages",
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
        FROM raw_example.messages
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

#: A busy Wazuh deployment exceeds 20,000 alerts/day, so a 7-year trend over
#: per-record facts scans ~51M rows. The rollup reduces that to ~1.2M — 42x less
#: — which is what makes a long-horizon dashboard usable on a modest host.
#:
#: Per-record facts are retained for the full period regardless, so this grain is
#: a performance optimisation that can be rebuilt, not a one-way door.
#:
#: EVERY DIMENSION HERE MUST BE LOW-CARDINALITY. rule_level has 16 values and
#: decoder a few dozen, so the daily rollup stays small. agent_name is the
#: tempting mistake: it looks like an obvious dimension and is bounded only by
#: fleet size, so on a 5,000-agent estate it would produce a rollup larger than
#: the fact table it summarises. High-cardinality attributes stay in the facts,
#: where a dashboard can filter to one agent without paying for all of them.
WAZUH = Target(
    name="wazuh_alerts",
    raw_table="raw_wazuh.alerts",
    fact_table="mart_fact_wazuh_alerts",
    fact_date_expr="occurred_at",
    upsert_sql="""
        INSERT INTO mart_fact_wazuh_alerts
            (alert_id, occurred_at, rule_id, rule_level, rule_description,
             rule_group, agent_id, agent_name, decoder, location)
        SELECT
            source_id,
            (payload->>'timestamp')::timestamptz,
            payload->'rule'->>'id',
            (payload->'rule'->>'level')::int,
            payload->'rule'->>'description',
            payload->'rule'->'groups'->>0,
            payload->'agent'->>'id',
            payload->'agent'->>'name',
            payload->'decoder'->>'name',
            payload->>'location'
        FROM raw_wazuh.alerts
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Alerts are append-only, so this conflict clause fires only on the
        -- connector's deliberate re-read of its late-arrival overlap window.
        -- It exists so that overlap costs nothing but a rewrite of identical
        -- values; without it the overlap would be a duplicate-key crash.
        ON CONFLICT (alert_id, occurred_at) DO UPDATE SET
            rule_level       = EXCLUDED.rule_level,
            rule_description = EXCLUDED.rule_description,
            rule_group       = EXCLUDED.rule_group,
            decoder          = EXCLUDED.decoder
    """,
    rollup_table="mart_rollup_wazuh_daily",
    rollup_sql="""
        INSERT INTO mart_rollup_wazuh_daily
            (day, rule_level, rule_group, decoder, alert_count)
        SELECT occurred_at::date, rule_level, rule_group, decoder, count(*)
        FROM mart_fact_wazuh_alerts
        WHERE occurred_at::date = ANY(%(days)s)
        GROUP BY 1, 2, 3, 4
    """,
)

TARGETS = {t.name: t for t in (EXAMPLE, WAZUH)}
