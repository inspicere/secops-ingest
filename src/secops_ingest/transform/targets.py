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
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_example_messages (
            message_id  text        NOT NULL,
            reported_at timestamptz NOT NULL,
            updated_at  timestamptz,
            status      text,
            category    text,
            severity    text,
            PRIMARY KEY (message_id, reported_at)
        ) PARTITION BY RANGE (reported_at);
        CREATE INDEX IF NOT EXISTS mart_fact_example_messages_reported_at_idx
            ON mart_fact_example_messages (reported_at);
    """,
    rollup_ddl="""
        CREATE TABLE IF NOT EXISTS mart_rollup_example_daily (
            day           date   NOT NULL,
            status        text,
            category      text,
            severity      text,
            message_count bigint NOT NULL
        );
        CREATE INDEX IF NOT EXISTS mart_rollup_example_daily_day_idx
            ON mart_rollup_example_daily (day);
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
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_wazuh_alerts (
            alert_id         text        NOT NULL,
            occurred_at      timestamptz NOT NULL,
            rule_id          text,
            rule_level       integer,
            rule_description text,
            rule_group       text,
            agent_id         text,
            agent_name       text,
            decoder          text,
            location         text,
            PRIMARY KEY (alert_id, occurred_at)
        ) PARTITION BY RANGE (occurred_at);
        CREATE INDEX IF NOT EXISTS mart_fact_wazuh_alerts_occurred_at_idx
            ON mart_fact_wazuh_alerts (occurred_at);
        -- agent_name is excluded from the rollup on cardinality grounds, so
        -- per-agent questions are answered here instead. This index is what
        -- makes that affordable.
        CREATE INDEX IF NOT EXISTS mart_fact_wazuh_alerts_agent_idx
            ON mart_fact_wazuh_alerts (agent_name);
    """,
    rollup_ddl="""
        CREATE TABLE IF NOT EXISTS mart_rollup_wazuh_daily (
            day         date   NOT NULL,
            rule_level  integer,
            rule_group  text,
            decoder     text,
            alert_count bigint NOT NULL
        );
        CREATE INDEX IF NOT EXISTS mart_rollup_wazuh_daily_day_idx
            ON mart_rollup_wazuh_daily (day);
    """,
)

#: Vulnerability findings. The counterpart to WAZUH in the transform layer, for
#: the same reason the connectors are a pair: Wazuh alerts are events that
#: happened, DefectDojo findings are open items whose STATE changes for months.
#:
#: The grain is the DISCOVERY date, not the modification date. That is what makes
#: the rollup correct under mutation: when a finding discovered in July is
#: mitigated today, its raw row still carries July as _event_time, so the runner
#: recomputes July's rollup and the day it belongs to gets the new state. A
#: modification-date grain would scatter one finding's history across every day
#: somebody touched it.
#:
#: MEASURES ARE ADDITIVE ON PURPOSE. days_to_mitigate is stored as a SUM and a
#: COUNT rather than a mean, because means do not re-aggregate: averaging the
#: daily averages over a month weights a day with two findings the same as a day
#: with two hundred. Storing both terms lets the dashboard divide at whatever
#: grain it is actually showing, and get the right answer at all of them.
DEFECTDOJO = Target(
    name="defectdojo_findings",
    raw_table="raw_defectdojo.findings",
    fact_table="mart_fact_defectdojo_findings",
    fact_date_expr="discovered_at",
    upsert_sql="""
        INSERT INTO mart_fact_defectdojo_findings
            (finding_id, discovered_at, created_at, last_status_update, mitigated_at,
             severity, status, cwe, cvss_score, component_name,
             sla_start_date, sla_expiration_date)
        SELECT
            source_id,
            COALESCE((payload->>'date')::date, (payload->>'created')::timestamptz::date),
            (payload->>'created')::timestamptz,
            (payload->>'last_status_update')::timestamptz,
            (payload->>'mitigated')::timestamptz,
            payload->>'severity',
            -- Order is a decision, not an accident. A finding can be several of
            -- these at once, and the first match wins: a false positive that was
            -- also closed is a false positive, not a mitigation, or the
            -- time-to-mitigate figures get credit for work nobody did.
            CASE
                WHEN (payload->>'false_p')::boolean        THEN 'false_positive'
                WHEN (payload->>'duplicate')::boolean      THEN 'duplicate'
                WHEN (payload->>'out_of_scope')::boolean   THEN 'out_of_scope'
                WHEN (payload->>'risk_accepted')::boolean  THEN 'risk_accepted'
                WHEN (payload->>'is_mitigated')::boolean   THEN 'mitigated'
                WHEN (payload->>'active')::boolean         THEN 'open'
                ELSE 'inactive'
            END,
            (payload->>'cwe')::int,
            (payload->>'cvssv3_score')::numeric,
            payload->>'component_name',
            (payload->>'sla_start_date')::date,
            (payload->>'sla_expiration_date')::date
        FROM raw_defectdojo.findings
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Every mutable column is refreshed. Unlike an append-only source, this
        -- clause is the normal path rather than the exception: most rows arrive
        -- because their state changed, not because they are new.
        ON CONFLICT (finding_id, discovered_at) DO UPDATE SET
            last_status_update = EXCLUDED.last_status_update,
            mitigated_at       = EXCLUDED.mitigated_at,
            severity           = EXCLUDED.severity,
            status             = EXCLUDED.status,
            cvss_score         = EXCLUDED.cvss_score,
            sla_expiration_date = EXCLUDED.sla_expiration_date
    """,
    rollup_table="mart_rollup_defectdojo_daily",
    # severity has 5 values and status 7, so a day holds at most ~35 rows.
    # component_name is deliberately absent: ~thousands of distinct values would
    # make the rollup larger than the facts it summarises. It stays in the fact
    # table, where a dashboard can filter to one component without paying for all.
    rollup_sql="""
        INSERT INTO mart_rollup_defectdojo_daily
            (day, severity, status, finding_count,
             days_to_mitigate_sum, days_to_mitigate_count, sla_breached_on_close_count)
        SELECT
            discovered_at,
            severity,
            status,
            count(*),
            -- SUM and COUNT, never an average. See the note above the target.
            COALESCE(SUM(mitigated_at::date - discovered_at)
                     FILTER (WHERE mitigated_at IS NOT NULL), 0),
            COUNT(*) FILTER (WHERE mitigated_at IS NOT NULL),
            -- Only breaches that are already SETTLED are counted here. Whether a
            -- still-open finding has blown its SLA is a function of now(), and
            -- this table is only recomputed when a finding changes -- so a
            -- stored open-breach count would be correct on the day it was
            -- written and silently drift wrong every day after. That figure has
            -- to be computed at query time against sla_expiration_date on the
            -- facts, which are retained for the full reporting period.
            COUNT(*) FILTER (
                WHERE mitigated_at IS NOT NULL
                  AND sla_expiration_date IS NOT NULL
                  AND mitigated_at::date > sla_expiration_date
            )
        FROM mart_fact_defectdojo_findings
        WHERE discovered_at = ANY(%(days)s)
        GROUP BY 1, 2, 3
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_defectdojo_findings (
            finding_id          text NOT NULL,
            discovered_at       date NOT NULL,
            created_at          timestamptz,
            last_status_update  timestamptz,
            mitigated_at        timestamptz,
            severity            text,
            status              text,
            cwe                 integer,
            cvss_score          numeric(4,1),
            component_name      text,
            sla_start_date      date,
            sla_expiration_date date,
            PRIMARY KEY (finding_id, discovered_at)
        ) PARTITION BY RANGE (discovered_at);
        CREATE INDEX IF NOT EXISTS mart_fact_defectdojo_findings_discovered_idx
            ON mart_fact_defectdojo_findings (discovered_at);
        -- The rollup deliberately does NOT precompute open-SLA breaches, because
        -- that answer is a function of now() and would drift. It is computed at
        -- query time instead, and this partial index is what makes that cheap:
        -- it covers exactly the still-open rows the question asks about.
        CREATE INDEX IF NOT EXISTS mart_fact_defectdojo_findings_open_sla_idx
            ON mart_fact_defectdojo_findings (sla_expiration_date)
            WHERE mitigated_at IS NULL;
    """,
    rollup_ddl="""
        CREATE TABLE IF NOT EXISTS mart_rollup_defectdojo_daily (
            day                         date   NOT NULL,
            severity                    text,
            status                      text,
            finding_count               bigint NOT NULL,
            days_to_mitigate_sum        bigint NOT NULL,
            days_to_mitigate_count      bigint NOT NULL,
            sla_breached_on_close_count bigint NOT NULL
        );
        CREATE INDEX IF NOT EXISTS mart_rollup_defectdojo_daily_day_idx
            ON mart_rollup_defectdojo_daily (day);
    """,
)

TARGETS = {t.name: t for t in (EXAMPLE, WAZUH, DEFECTDOJO)}
