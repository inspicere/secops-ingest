# secops-ingest

Pull security-vendor telemetry into PostgreSQL, with pluggable secret backends.

Security tools each hold their own slice of the picture and each expose it through their own
API. This is the small, unglamorous layer that gets those records into one database on a
schedule, without losing any, without duplicating any, and without writing credentials to disk.
What reads the result afterwards — Metabase, Grafana, Superset, `psql` — is not this project's
concern.

**Core has no third-party dependencies.** `pip install secops-ingest` pulls nothing but the
standard library. Every backend and driver is opt-in.

## Requirements

- Python 3.11+
- PostgreSQL 14+

PostgreSQL is a requirement, not an implementation detail. Declarative partitioning, `JSONB`,
and `ON CONFLICT` are load-bearing here, and a database abstraction would cost far more than it
returns. If you need a different store, this is the wrong library.

## Install

```bash
pip install secops-ingest                 # core: env + file secret backends
pip install "secops-ingest[postgres]"     # psycopg, to actually write rows
pip install "secops-ingest[vault]"        # HashiCorp Vault backend
pip install "secops-ingest[delinea]"      # Delinea Secret Server backend
```

## Try it without any credential

A reference connector ships with the package. It emits synthetic records so the whole path —
fetch, land, watermark, run bookkeeping — can be exercised with no vendor account:

```bash
python -m secops_ingest example --dry-run
```

Its records are anchored to the top of the current hour rather than to `now()`, so two runs
inside the same hour produce byte-identical rows. That is deliberate: it is what makes upsert
idempotency observable. With a `now()` anchor every run mints new ids, and a re-run always looks
like it inserted correctly whether or not it did.

## Connectors against real products

`example` proves the wiring; **`wazuh`** proves the contract. Wazuh is an
open-source (GPLv2) XDR/SIEM platform, so the connector can be exercised against
software anyone can install rather than against a synthetic fixture:

```bash
export SECOPS_WAZUH_URL=https://127.0.0.1:9200
export SECOPS_SECRETS_BACKEND=env
export SECOPS_SECRET_WAZUH_INDEXER_PASSWORD=...
python -m secops_ingest wazuh --dry-run
```

Speaking HTTP to a GPL-licensed server places no licence obligation on this
Apache-2.0 client — nothing here links to or vendors Wazuh code.

It is also the connector worth reading before writing your own, because it has
the problem the synthetic example does not. Wazuh alerts are append-only, so the
event time *is* the watermark — and that is exactly what makes late arrival
dangerous. An agent that was offline can index an alert older than a watermark
already passed, and a strict `> cursor` query would step over it and never look
back. The loss would be silent.

So each run re-reads a trailing window (`SECOPS_WAZUH_LAG_SECONDS`, default 900).
Re-reading costs nothing because landing is an upsert keyed on
`(source_id, _event_time)`. That trade — a little duplicate work against losing
records — is the one most connectors get wrong in the same direction.

### DefectDojo — the other half of the watermark problem

`wazuh` and `defectdojo` are a deliberate pair, because between them they cover
both shapes a connector can face:

| | Wazuh | DefectDojo |
|---|---|---|
| Records | append-only | mutate for months |
| Watermark | the event time itself | a separate modification field |
| The hazard | late arrival leaves a silent gap | watermarking on creation misses every change |

A DefectDojo finding is created once, then triaged, verified, risk-accepted,
mitigated, reopened. A watermark on `created` reads it once on the day it
appears and never again — so findings closed months ago still show as open, and
the SLA numbers are wrong in the flattering direction. Nothing errors.

Its API also has two traps worth knowing before writing any client for it:

**Unknown query parameters are ignored, not rejected.** `?nonsense=xyzzy`
returns the full collection with HTTP 200. A wrong parameter name does not fail
— it silently returns everything.

**The ordering parameter is `o=`, not `ordering=`.** The conventional name is
accepted and ignored, per the first trap.

There is no server-side time filter at all, so this connector sorts by
modification time descending and stops at the first record older than the
watermark. Against a ~50,000-finding instance that reads five records instead of
fifty thousand.

## Secret backends

Selected by `SECOPS_SECRETS_BACKEND`, defaulting to `env`.

| Backend | Use | Ships in core |
|---|---|---|
| `env` | development, CI, containers | yes |
| `file` | systemd `LoadCredential=`, Docker and Kubernetes secrets | yes |
| `vault` | HashiCorp Vault, or OpenBao | `[vault]` |
| `delinea` | Delinea Secret Server | `[delinea]` |

```python
from secops_ingest.secrets import get_provider

provider = get_provider()           # or get_provider("file", directory="/run/secrets")
token = provider.get("wazuh_indexer_password")
```

The `vault` backend speaks the Vault HTTP API, so it works against
[OpenBao](https://openbao.org/) unchanged — the MPL-2.0 fork of Vault's last
open-source branch, now under Linux Foundation governance. That matters here:
HashiCorp Vault moved to the BUSL in 2023, and a package claiming pluggable,
open backends should be able to name one that is actually open.

CI runs the provider's integration tests against a live OpenBao server on every
push, so this is demonstrated rather than asserted. To run them yourself:

```bash
docker run -d -p 8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=root \
    quay.io/openbao/openbao:latest server -dev
pip install -e ".[vault,dev]"
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root pytest tests/secrets -v
```

Without `VAULT_ADDR` those tests skip, so the default `pytest` run still needs
no network and no server.

The interface is one method:

```python
class SecretProvider(ABC):
    @abstractmethod
    def get(self, name: str) -> str: ...
```

Resisting a richer interface — versions, leases, metadata — is deliberate. Every addition is a
compatibility burden across backends that support it unevenly, and the common case needs none
of it.

### Adding a backend without forking

Backends are discovered through entry points, so a new one ships as its own package:

```toml
[project.entry-points."secops_ingest.secret_providers"]
my_backend = "my_package.provider:MyProvider"
```

`get_provider("my_backend")` then works with no change here and no pull request. AWS Secrets
Manager, Azure Key Vault, 1Password, or an internal system are all somebody else's package.

## Writing a connector

A source is a plain object with four methods and two attributes. No base class to inherit, no
registration step — drop it in `secops_ingest/sources/` and expose `SOURCE`.

```python
class MySource:
    name = "mysource"
    table = "raw_mysource.events"

    def authenticate(self):
        # Fetch once per run, hold in memory. Never write it down.
        return get_provider().get("mysource_api_key")

    def fetch(self, creds, cursor):
        """Yield records strictly newer than `cursor`."""

    def to_row(self, record, run_id) -> tuple:
        """Map one record to a database row."""

    def watermark_of(self, record):
        """Return the value that orders records for resumption."""

SOURCE = MySource()
```

Then:

```bash
python -m secops_ingest mysource
```

Two things the reference connector demonstrates and that are easy to get wrong:

**Partition on a timestamp that never changes.** `_event_time` comes from the record's creation
time. The watermark uses its *update* time. Partitioning on the update time moves rows between
partitions whenever a record changes.

**The watermark is not the event time.** Vendors mutate records after creation. Resuming from a
creation-time high-water mark silently misses every edit to a record you already have.

## Transform stage

Raw tables are a bounded re-derivation buffer; retention lives in the reporting layer. A target
declares its tables and the SQL that derives reporting rows, and the runner owns everything that
must not vary — watermarking, rollup recomputation, the coverage ledger, run bookkeeping.

```bash
python -m secops_ingest.transform <target>
```

`Target` validates itself on construction, because two of these mistakes are silent:

- `upsert_sql` must reference `%(since)s`, or every run reprocesses the entire raw table
- a bare `%(since)s` inside `IS NULL` must be cast (`%(since)s::timestamptz`); PostgreSQL cannot
  infer a type for it and raises `AmbiguousParameter`

## Warehouse schema

The DDL ships with the package and is emitted as SQL, never executed:

```bash
python -m secops_ingest.schema | psql "$DSN"
python -m secops_ingest.schema --target wazuh_alerts --partitions-ahead 6
```

Three layers: `raw_*` landing tables partitioned monthly on an immutable event
time, `control` for run history, watermarks and the coverage ledger, and
`mart_*` facts and rollups declared by each transform target.

Emitting rather than applying keeps the schema usable from psql, Ansible, a
migration tool, or a code review — and means this part needs no database driver.
Everything is `IF NOT EXISTS` or a guarded `DO` block, so re-running is safe.

Three things in it are load-bearing and easy to undo by accident:

**`_event_time` must come from an immutable field.** It is the partition key.
Sources that mutate records watermark on the modification time so state changes
are re-read; partitioning on that would move a row between partitions every time
somebody touched it.

**The month arithmetic is PostgreSQL's.** Adding an "average month" of seconds in
application code drifts and eventually skips a month — which surfaces as inserts
failing at midnight on the first, with no prior warning. Keep the lookahead
window maintained on every deploy rather than assuming it.

**The coverage ledger is what makes raw expiry safe.** Raw is a bounded
re-derivation buffer, so dropping a partition is irreversible. Nothing may drop a
period without a positive row in `control.transform_coverage` recording that the
period's reporting rows exist.

## Credential handling

- Secrets are fetched once per run and held in memory. Nothing is cached to disk.
- `SecretNotFound` carries the secret's *name*, never its value.
- Secret names are validated before use, so a name cannot traverse out of a provider's directory.
- A process-wide redaction filter scrubs registered secret values from log records, including
  from tracebacks. Register anything sensitive you obtain by other means:

```python
from secops_ingest.redaction import register_secret
register_secret(token)
```

Redaction is a backstop, not a licence to log credentials.

## Scheduling

Scheduling is deliberately external. The interface is a CLI, so systemd timers, cron, and
Kubernetes `CronJob` all work unchanged. Example units are in [`examples/systemd/`](examples/systemd/).

## What this deliberately does not do

- **No Metabase coupling.** The workers write PostgreSQL. Nothing here knows what reads it.
- **No database abstraction.** See Requirements.
- **No scheduler.** See above.
- **No opinionated logging.** Standard library only; configure it however you already do.
- **No cross-source correlation.** Landing records correctly is a separable problem from joining
  them, and doing it here would couple every connector to every other.

## License

Apache-2.0. See [LICENSE](LICENSE).

Apache rather than MIT for the explicit patent grant, which matters for a project implementing
several commercial vendors' API protocols.
