# Security Policy

This project brokers credentials for security vendors' APIs. A defect here can expose the keys
to several security products at once, so reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this
repository. That opens a private channel visible only to the maintainers, and it works without
either of us publishing an email address.

Useful to include, if you have it:

- what an attacker gains, and what access they need first
- affected version or commit
- a minimal reproduction
- your assessment of severity

You will get an acknowledgement within a week. If a report is confirmed, you will be told the
intended fix and timing, and credited in the release notes unless you would rather not be.

## Scope

In scope:

- disclosure of secret material through logs, exceptions, tracebacks, or error messages
- a secret name that escapes its provider's namespace or directory
- SQL injection through connector-supplied identifiers or values
- privilege assumptions in the example systemd units or documented database grants -- for
  example a worker role able to write another job's control tables, or `control.pack`
- dependency confusion or entry-point hijacking in the backend or pack discovery mechanism,
  including a way past `SECOPS_ALLOWED_PACKS`
- a dependency version or hash in `requirements/deploy.txt` that does not match what it claims

Out of scope:

- vulnerabilities in PostgreSQL, HashiCorp Vault, Delinea Secret Server, or any vendor API —
  report those to their maintainers
- a deployment that reads secrets from a world-readable file, or otherwise ignores the guidance
  in the README
- anything requiring an attacker who already has code execution as the worker's user; at that
  point the credentials are theirs regardless

## What the defaults assume

- **Database roles are least-privilege per job.** `python -m secops_ingest.schema` grants each
  worker write access to its own `control` tables only, and nothing writes `control.pack`
  except the schema owner. One shared ingest role still covers every raw schema unless a
  `--remote-ingest-role` confines a writer to one; within `control.ingest_run` and
  `control.ingest_watermark`, any ingest role can still write any source's rows.
- **Pack code is trusted code.** Without `SECOPS_ALLOWED_PACKS`, every installed distribution
  that advertises the `secops_ingest.packs` entry point is imported at startup of every worker.
- **Dependencies are only as pinned as the install.** The extras' ranges are capped by major
  version; exact versions and hashes are enforced only when `requirements/deploy.txt` is
  installed with `--require-hashes`.

## Handling secrets in reports

If a reproduction involves real credentials, redact them. If you believe you have found live
credentials belonging to someone else, do not include them at all — say what you found and where,
and we will chase it down.
