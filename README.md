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

## Secret backends

Selected by `SECOPS_SECRETS_BACKEND`, defaulting to `env`.

| Backend | Use | Ships in core |
|---|---|---|
| `env` | development, CI, containers | yes |
| `file` | systemd `LoadCredential=`, Docker and Kubernetes secrets | yes |
| `vault` | HashiCorp Vault | `[vault]` |
| `delinea` | Delinea Secret Server | `[delinea]` |

```python
from secops_ingest.secrets import get_provider

provider = get_provider()           # or get_provider("file", directory="/run/secrets")
token = provider.get("phisher_api_key")
```

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
