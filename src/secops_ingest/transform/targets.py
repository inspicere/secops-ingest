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

#: XSOAR is the anchor of the incident lifecycle: it holds ~2.75 years against
#: XDR's 325-day retention, and it carries the XDR incident id on every mirrored
#: incident. Build and backfill this before the XDR fact.
#:
#: NOTE ON THIS INSTANCE: every sampled incident was closed (status=2, 500/500),
#: because the dominant incident type is an automated remediation playbook. MTTR
#: here measures automation latency, not analyst response. `open_duration_s` is
#: the instance's own measure. Derived `time_to_resolve` lives on the lifecycle
#: fact table built in a later task, since the same incident exists on both XSOAR
#: and XDR sides and measuring it twice would double-count.
#:
#: The payload extraction is deliberately duplicated in INCIDENT_LIFECYCLE.
#: Editing one without the other will make them drift.
XSOAR_INCIDENTS = Target(
    name="xsoar_incidents",
    raw_table="raw_xsoar.incidents",
    fact_table="mart_fact_xsoar_incidents",
    fact_date_expr="created_at",
    upsert_sql="""
        INSERT INTO mart_fact_xsoar_incidents
            (incident_id, created_at, modified_at, closed_at, status, severity,
             owner, incident_type, source_brand, xdr_incident_id, open_duration_s)
        SELECT
            source_id,
            (payload->>'created')::timestamptz,
            (payload->>'modified')::timestamptz,
            -- "Not closed" has no single representation here, and no open
            -- incident existed to sample. Treat absent, empty and the Go zero
            -- time as open; anything else is a real resolution timestamp.
            NULLIF(NULLIF(payload->>'closed', ''), '0001-01-01T00:00:00Z')::timestamptz,
            -- Integers, not strings: status 2 is closed. The original runbook
            -- read these as text and would have rendered "2" on a dashboard.
            (payload->>'status')::int,
            (payload->>'severity')::int,
            payload->>'owner',
            payload->>'type',
            payload->>'sourceBrand',
            -- The join key. XSOAR carries the XDR incident id here on every
            -- mirrored incident; parentXDRIncident and CustomFields.xdrincidentid
            -- carry it too, and this one is the cheapest to reach.
            payload->>'dbotMirrorId',
            (payload->>'openDuration')::bigint
        FROM raw_xsoar.incidents
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Every mutable column is refreshed, as on DEFECTDOJO above.
        --
        -- xdr_incident_id in particular. dbotMirrorId is NOT necessarily set
        -- when the incident is created: mirroring is established afterwards, so
        -- an incident that lands before its mirror link is established arrives
        -- with a NULL join key. Leaving the column out of this list froze that
        -- NULL forever -- on the one column the table carries an index for, and
        -- the one the whole XSOAR/XDR integration joins on.
        ON CONFLICT (incident_id, created_at) DO UPDATE SET
            modified_at     = EXCLUDED.modified_at,
            closed_at       = EXCLUDED.closed_at,
            status          = EXCLUDED.status,
            severity        = EXCLUDED.severity,
            owner           = EXCLUDED.owner,
            incident_type   = EXCLUDED.incident_type,
            source_brand    = EXCLUDED.source_brand,
            xdr_incident_id = EXCLUDED.xdr_incident_id,
            open_duration_s = EXCLUDED.open_duration_s
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_xsoar_incidents (
            incident_id     text        NOT NULL,
            created_at      timestamptz NOT NULL,
            modified_at     timestamptz,
            closed_at       timestamptz,
            status          integer,
            severity        integer,
            owner           text,
            incident_type   text,
            source_brand    text,
            xdr_incident_id text,
            open_duration_s bigint,
            PRIMARY KEY (incident_id, created_at)
        ) PARTITION BY RANGE (created_at);
        CREATE INDEX IF NOT EXISTS mart_fact_xsoar_incidents_created_at_idx
            ON mart_fact_xsoar_incidents (created_at);
        -- NOT the lifecycle join's index. INCIDENT_LIFECYCLE is anchored on
        -- raw_xsoar.incidents and reads dbotMirrorId straight out of the raw
        -- payload, so it never touches this table at all. Kept because
        -- ad-hoc joins and dashboard filters on the XDR id do read it here, and
        -- without the index each one is a sequential scan of the whole fact
        -- table -- but nothing in this package depends on it.
        CREATE INDEX IF NOT EXISTS mart_fact_xsoar_incidents_xdr_id_idx
            ON mart_fact_xsoar_incidents (xdr_incident_id);
    """,
)

#: XDR timestamps are epoch MILLISECONDS throughout. Every one of them is
#: divided by 1000 before to_timestamp; missing that puts the row in roughly the
#: year 56,000, which is obvious on a time-series chart and invisible in a count.
XDR_INCIDENTS = Target(
    name="xdr_incidents",
    raw_table="raw_xdr.incidents",
    fact_table="mart_fact_xdr_incidents",
    fact_date_expr="created_at",
    upsert_sql="""
        INSERT INTO mart_fact_xdr_incidents
            (incident_id, created_at, modified_at, resolved_at, status, severity,
             description, alert_count, high_severity_alert_count,
             med_severity_alert_count, low_severity_alert_count,
             host_count, user_count, assignee)
        SELECT
            source_id,
            to_timestamp((payload->>'creation_time')::bigint / 1000),
            to_timestamp((payload->>'modification_time')::bigint / 1000),
            -- resolved_timestamp is 0 on an unresolved incident rather than
            -- null, and 0 converts to 1970 instead of failing.
            CASE WHEN COALESCE((payload->>'resolved_timestamp')::bigint, 0) > 0
                 THEN to_timestamp((payload->>'resolved_timestamp')::bigint / 1000)
            END,
            payload->>'status',
            payload->>'severity',
            payload->>'description',
            (payload->>'alert_count')::int,
            (payload->>'high_severity_alert_count')::int,
            (payload->>'med_severity_alert_count')::int,
            (payload->>'low_severity_alert_count')::int,
            (payload->>'host_count')::int,
            (payload->>'user_count')::int,
            payload->>'assigned_user_mail'
        FROM raw_xdr.incidents
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- The per-severity breakdown is refreshed WITH alert_count, never
        -- without it. An incident accrues alerts after it opens; refreshing the
        -- total while freezing its components produced rows reading
        -- alert_count = 10 over a breakdown summing to 3, which is not a
        -- partially stale figure but an internally contradictory one -- and it
        -- is invisible in either number read on its own.
        --
        -- host_count, user_count and description move for the same reason: an
        -- incident grows to cover more hosts and users as it is triaged.
        ON CONFLICT (incident_id, created_at) DO UPDATE SET
            modified_at               = EXCLUDED.modified_at,
            resolved_at               = EXCLUDED.resolved_at,
            status                    = EXCLUDED.status,
            severity                  = EXCLUDED.severity,
            description               = EXCLUDED.description,
            alert_count               = EXCLUDED.alert_count,
            high_severity_alert_count = EXCLUDED.high_severity_alert_count,
            med_severity_alert_count  = EXCLUDED.med_severity_alert_count,
            low_severity_alert_count  = EXCLUDED.low_severity_alert_count,
            host_count                = EXCLUDED.host_count,
            user_count                = EXCLUDED.user_count,
            assignee                  = EXCLUDED.assignee
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_xdr_incidents (
            incident_id               text        NOT NULL,
            created_at                timestamptz NOT NULL,
            modified_at               timestamptz,
            resolved_at               timestamptz,
            status                    text,
            severity                  text,
            description               text,
            alert_count               integer,
            high_severity_alert_count integer,
            med_severity_alert_count  integer,
            low_severity_alert_count  integer,
            host_count                integer,
            user_count                integer,
            assignee                  text,
            PRIMARY KEY (incident_id, created_at)
        ) PARTITION BY RANGE (created_at);
        CREATE INDEX IF NOT EXISTS mart_fact_xdr_incidents_created_at_idx
            ON mart_fact_xdr_incidents (created_at);
    """,
)

#: Measured 2026-09-14: ~17,700 alerts/day, 2,650,762 in the collection. That is
#: ~6.5M fact rows a year against 9,715 incidents, so the rollup is not an
#: optimisation to add later -- it is what makes a long-horizon dashboard open
#: at all.
#:
#: EVERY DIMENSION HERE MUST BE LOW-CARDINALITY. severity has a handful of
#: values, category and source a few dozen. endpoint_id is the tempting mistake:
#: bounded only by fleet size (1,630 here), it would produce a daily rollup
#: larger than the fact table it summarises. High-cardinality attributes stay in
#: the facts, where a dashboard can filter to one endpoint without paying for
#: all of them.
XDR_ALERTS = Target(
    name="xdr_alerts",
    raw_table="raw_xdr.alerts",
    fact_table="mart_fact_xdr_alerts",
    fact_date_expr="detected_at",
    upsert_sql="""
        INSERT INTO mart_fact_xdr_alerts
            (alert_id, detected_at, indexed_at, severity, category, source,
             alert_name, resolution_status, endpoint_id, host_name, agent_os_type)
        SELECT
            source_id,
            to_timestamp((payload->>'detection_timestamp')::bigint / 1000),
            to_timestamp((payload->>'local_insert_ts')::bigint / 1000),
            payload->>'severity',
            payload->>'category',
            payload->>'source',
            payload->>'name',
            payload->>'resolution_status',
            payload->>'endpoint_id',
            payload->>'host_name',
            payload->>'agent_os_type'
        FROM raw_xdr.alerts
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Fires only on the connector's deliberate late-arrival overlap, which
        -- re-reads a trailing window every run. Without this clause that
        -- overlap would be a duplicate-key crash instead of a rewrite of
        -- identical values.
        ON CONFLICT (alert_id, detected_at) DO UPDATE SET
            resolution_status = EXCLUDED.resolution_status,
            indexed_at        = EXCLUDED.indexed_at
    """,
    rollup_table="mart_rollup_xdr_alerts_daily",
    rollup_sql="""
        INSERT INTO mart_rollup_xdr_alerts_daily
            (day, severity, category, source, alert_count)
        SELECT detected_at::date, severity, category, source, count(*)
        FROM mart_fact_xdr_alerts
        WHERE detected_at::date = ANY(%(days)s)
        GROUP BY 1, 2, 3, 4
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_xdr_alerts (
            alert_id          text        NOT NULL,
            detected_at       timestamptz NOT NULL,
            indexed_at        timestamptz,
            severity          text,
            category          text,
            source            text,
            alert_name        text,
            resolution_status text,
            endpoint_id       text,
            host_name         text,
            agent_os_type     text,
            PRIMARY KEY (alert_id, detected_at)
        ) PARTITION BY RANGE (detected_at);
        CREATE INDEX IF NOT EXISTS mart_fact_xdr_alerts_detected_at_idx
            ON mart_fact_xdr_alerts (detected_at);
    """,
    rollup_ddl="""
        CREATE TABLE IF NOT EXISTS mart_rollup_xdr_alerts_daily (
            day         date   NOT NULL,
            severity    text,
            category    text,
            source      text,
            alert_count bigint NOT NULL
        );
        CREATE INDEX IF NOT EXISTS mart_rollup_xdr_alerts_daily_day_idx
            ON mart_rollup_xdr_alerts_daily (day);
    """,
)

#: One row per endpoint per snapshot. The grain is the point: a current-state
#: table answers "what is the estate now" and destroys the answer to "when did
#: this agent stop checking in", which is the question policy health is actually
#: about. 1,630 endpoints daily is ~595k rows a year -- small enough that no
#: rollup is needed.
XDR_ENDPOINTS = Target(
    name="xdr_endpoints",
    raw_table="raw_xdr.endpoint_snapshots",
    fact_table="mart_fact_xdr_endpoint_snapshots",
    fact_date_expr="snapshot_at",
    upsert_sql="""
        INSERT INTO mart_fact_xdr_endpoint_snapshots
            (endpoint_id, snapshot_at, endpoint_name, endpoint_status,
             agent_version, content_version, os_type, last_seen_at,
             is_isolated, operational_status, policy_name, extensions_policy)
        SELECT
            source_id,
            _event_time,
            payload->>'endpoint_name',
            payload->>'endpoint_status',
            payload->>'agent_version',
            payload->>'content_version',
            payload->>'os_type',
            CASE WHEN COALESCE((payload->>'last_seen')::bigint, 0) > 0
                 THEN to_timestamp((payload->>'last_seen')::bigint / 1000)
            END,
            payload->>'is_isolated',
            payload->>'operational_status',
            -- The policy columns. Verified present on the live payload
            -- 2026-09-14. Without them this target answers "is the agent
            -- running" but not "is the right policy applied to it", which is
            -- the half of policy health that this table exists for.
            payload->>'assigned_prevention_policy',
            payload->>'assigned_extensions_policy'
        FROM raw_xdr.endpoint_snapshots
        WHERE %(since)s::timestamptz IS NULL OR _ingested_at > %(since)s::timestamptz
        -- Both policy columns are mutable: a reassignment is exactly the drift
        -- this table is here to make visible, so a re-landed snapshot must be
        -- able to correct them.
        ON CONFLICT (endpoint_id, snapshot_at) DO UPDATE SET
            endpoint_status    = EXCLUDED.endpoint_status,
            agent_version      = EXCLUDED.agent_version,
            content_version    = EXCLUDED.content_version,
            last_seen_at       = EXCLUDED.last_seen_at,
            operational_status = EXCLUDED.operational_status,
            policy_name        = EXCLUDED.policy_name,
            extensions_policy  = EXCLUDED.extensions_policy
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_xdr_endpoint_snapshots (
            endpoint_id        text        NOT NULL,
            snapshot_at        timestamptz NOT NULL,
            endpoint_name      text,
            endpoint_status    text,
            agent_version      text,
            content_version    text,
            os_type            text,
            last_seen_at       timestamptz,
            is_isolated        text,
            operational_status text,
            policy_name        text,
            extensions_policy  text,
            PRIMARY KEY (endpoint_id, snapshot_at)
        ) PARTITION BY RANGE (snapshot_at);
        CREATE INDEX IF NOT EXISTS mart_fact_xdr_endpoint_snapshots_snapshot_at_idx
            ON mart_fact_xdr_endpoint_snapshots (snapshot_at);
    """,
)

#: The end-to-end view the whole integration exists for:
#:
#:     XDR incident created -> XSOAR incident created -> XSOAR closed
#:
#: ANCHORED ON XSOAR, AND THE DIRECTION IS LOAD-BEARING. Measured 2026-09-14:
#: XSOAR holds 48,678 incidents back to 2023-12-10; XDR holds 9,715 with 325
#: days of retention. An inner join, or a join anchored on XDR, would silently
#: discard every incident older than XDR's retention -- which is most of them --
#: and the loss would look like a smaller, tidier dataset rather than an error.
#:
#: UNMATCHED ROWS ARE EXPECTED AND ARE TWO DIFFERENT THINGS. Roughly 10.5% of
#: XSOAR incidents did not come from XDR at all (other feeds, and a manual
#: source); separately, XDR-sourced incidents whose XDR record has aged out
#: carry an id that no longer resolves. Collapsing those into one "unmatched"
#: bucket turns a data-availability gap into an apparent business fact, so
#: join_status keeps them apart on the dashboard. A third unmatched population,
#: `pending_xdr`, is split out of the aged-out one for the reason below.
#:
#: DO NOT SUM MTTR ACROSS THE TWO FACT TABLES. The same incident exists on both
#: sides. This table is the only correct place to measure the lifecycle.
#:
#: `pending_xdr` EXISTS BECAUSE THE WATERMARK ONLY WATCHES THE XSOAR SIDE.
#: raw_table is raw_xsoar.incidents, so the runner's watermark is
#: max(_ingested_at) over XSOAR raw alone and the incremental predicate is
#: `x._ingested_at > since`. A row is therefore re-derived only when its XSOAR
#: raw row lands again. An incident whose XDR counterpart lands AFTER it does
#: would keep its unmatched classification and a NULL xdr_resolved_at forever,
#: because this instance auto-closes incidents: `modified` stops advancing, the
#: XSOAR raw row never re-lands, and nothing ever re-runs the join for it.
#:
#: So an unmatched incident that is still inside XDR's 325-day retention is
#: classified `pending_xdr` rather than `xdr_aged_out`, and the WHERE clause
#: re-derives exactly those rows on every run via an EXISTS against this very
#: fact table. This is SELF-LIMITING: the three terminal states (`matched`,
#: `non_xdr_source`, and a genuine `xdr_aged_out` past the retention horizon)
#: are never retried, so the retry set only shrinks as the XDR side arrives or
#: the incident ages past 325 days.
#:
#: RUN ORDER MATTERS. `incident_lifecycle` must run AFTER `xdr_incidents` in any
#: deployment. Running it first is not a correctness bug any more -- that is the
#: point of `pending_xdr` -- but every new XDR-sourced incident then spends a
#: whole cycle in `pending_xdr` before it matches.
#:
#: FULL REBUILD RECIPE. There is no `--full` flag; the runner derives everything
#: from control.transform_watermark. To rebuild this table from the whole raw
#: buffer, clear its watermark and run it again::
#:
#:     DELETE FROM control.transform_watermark WHERE target='incident_lifecycle';
#:
#: The upsert is idempotent, so the rebuild rewrites rows rather than doubling
#: them, and the row count is bounded by what raw_xsoar.incidents still holds.
#:
#: The payload extraction is deliberately duplicated from XSOAR_INCIDENTS.
#: Editing one without the other will make them drift.
INCIDENT_LIFECYCLE = Target(
    name="incident_lifecycle",
    raw_table="raw_xsoar.incidents",
    fact_table="mart_fact_incident_lifecycle",
    fact_date_expr="created_at",
    upsert_sql="""
        INSERT INTO mart_fact_incident_lifecycle
            (xsoar_incident_id, created_at, xdr_incident_id, xdr_created_at,
             xdr_resolved_at, closed_at, status, severity, source_brand,
             incident_type, alert_count, join_status, time_to_resolve)
        SELECT
            x.source_id,
            (x.payload->>'created')::timestamptz,
            NULLIF(x.payload->>'dbotMirrorId', ''),
            d.created_at,
            d.resolved_at,
            NULLIF(NULLIF(x.payload->>'closed', ''), '0001-01-01T00:00:00Z')::timestamptz,
            (x.payload->>'status')::int,
            (x.payload->>'severity')::int,
            x.payload->>'sourceBrand',
            x.payload->>'type',
            d.alert_count,
            CASE
                WHEN d.incident_id IS NOT NULL                     THEN 'matched'
                WHEN COALESCE(x.payload->>'dbotMirrorId', '') = '' THEN 'non_xdr_source'
                WHEN (x.payload->>'created')::timestamptz
                     > now() - interval '325 days'                 THEN 'pending_xdr'
                ELSE                                                   'xdr_aged_out'
            END,
            NULLIF(NULLIF(x.payload->>'closed', ''), '0001-01-01T00:00:00Z')::timestamptz
              - (x.payload->>'created')::timestamptz
        FROM raw_xsoar.incidents x
        LEFT JOIN LATERAL (
            SELECT i.incident_id, i.created_at, i.resolved_at, i.alert_count
            FROM mart_fact_xdr_incidents i
            WHERE i.incident_id = NULLIF(x.payload->>'dbotMirrorId', '')
            ORDER BY i.created_at DESC
            LIMIT 1
        ) d ON true
        WHERE %(since)s::timestamptz IS NULL
           OR x._ingested_at > %(since)s::timestamptz
           OR EXISTS (
                SELECT 1 FROM mart_fact_incident_lifecycle l
                WHERE l.xsoar_incident_id = x.source_id
                  AND l.created_at = (x.payload->>'created')::timestamptz
                  AND l.join_status = 'pending_xdr')
        -- xdr_incident_id MUST be refreshed alongside join_status. It is
        -- derived from dbotMirrorId, which XSOAR sets when mirroring is
        -- established rather than at incident creation, so it is exactly as
        -- mutable as the status computed from it. Updating one and not the
        -- other is how a row comes to claim 'matched' while carrying no key to
        -- what it matched -- a self-contradiction no single column reveals.
        ON CONFLICT (xsoar_incident_id, created_at) DO UPDATE SET
            xdr_incident_id = EXCLUDED.xdr_incident_id,
            xdr_created_at  = EXCLUDED.xdr_created_at,
            xdr_resolved_at = EXCLUDED.xdr_resolved_at,
            closed_at       = EXCLUDED.closed_at,
            status          = EXCLUDED.status,
            severity        = EXCLUDED.severity,
            source_brand    = EXCLUDED.source_brand,
            incident_type   = EXCLUDED.incident_type,
            alert_count     = EXCLUDED.alert_count,
            join_status     = EXCLUDED.join_status,
            time_to_resolve = EXCLUDED.time_to_resolve
    """,
    fact_ddl="""
        CREATE TABLE IF NOT EXISTS mart_fact_incident_lifecycle (
            xsoar_incident_id text        NOT NULL,
            created_at        timestamptz NOT NULL,
            xdr_incident_id   text,
            xdr_created_at    timestamptz,
            xdr_resolved_at   timestamptz,
            closed_at         timestamptz,
            status            integer,
            severity          integer,
            source_brand      text,
            incident_type     text,
            alert_count       integer,
            join_status       text        NOT NULL,
            time_to_resolve   interval,
            PRIMARY KEY (xsoar_incident_id, created_at)
        ) PARTITION BY RANGE (created_at);
        CREATE INDEX IF NOT EXISTS mart_fact_incident_lifecycle_created_at_idx
            ON mart_fact_incident_lifecycle (created_at);
        CREATE INDEX IF NOT EXISTS mart_fact_incident_lifecycle_join_status_idx
            ON mart_fact_incident_lifecycle (join_status);
    """,
)

TARGETS = {
    t.name: t
    for t in (
        EXAMPLE,
        WAZUH,
        DEFECTDOJO,
        XSOAR_INCIDENTS,
        XDR_INCIDENTS,
        XDR_ALERTS,
        XDR_ENDPOINTS,
        INCIDENT_LIFECYCLE,
    )
}
